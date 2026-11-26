"""Closed-loop orchestrator uniting KeyAuthority, NodeGateways, AuditLedger, and WatchdogDetector."""

import hashlib
import secrets
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidTag

from src.sdk import (
    AuditLedger,
    KeyAuthority,
    LogEvent,
    NodeGateway,
    PeerInfo,
    RevocationNotice,
    WatchdogDetector,
    decrypt_chunk,
    encrypt_chunk,
    generate_identity_keypair,
    perform_handshake_initiator,
    perform_handshake_responder,
    serialize_private_keys,
    serialize_public_keys,
)

from .config import SentinelConfig

DEFAULT_TOPOLOGY_SERVICES = (
    "WebPortal",
    "Auth",
    "FileGateway",
    "Billing",
    "UserDB",
    "VaultDB",
    "PayrollDB",
    "Admin",
)


class SentinelRuntime:
    """Coordinates control plane, data plane gateways, tamper-evident telemetry, and containment."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self._lock = threading.RLock()
        self.authority = KeyAuthority(
            db_path=config.db_path,
            master_kek_hex=config.master_kek_hex,
            grace_period_seconds=config.grace_period_seconds,
        )

        # Persist dedicated ledger signing identity across restarts (separated from authority signing key per FIPS 204 Clause 8).
        self._ledger_signing_key = self.authority.get_or_create_ledger_signing_key()
        self.ledger = AuditLedger(
            ledger_path=config.ledger_path,
            signing_key=self._ledger_signing_key,
            verify_key=self._ledger_signing_key.public_key(),
            checkpoint_interval=config.checkpoint_interval,
        )

        self.detector = WatchdogDetector(
            allowed_paths=config.allowed_paths,
            clock_tolerance=config.clock_tolerance_seconds,
            lateral_window=config.lateral_window_seconds,
            lateral_max_hops=config.lateral_max_hops,
            critical_threshold=config.critical_severity_threshold,
            revocation_callback=self._on_watchdog_revocation,
            admin_nodes={"Admin"},
        )

        for rev in self.authority.list_revocations():
            self.detector.add_revoked_node(rev["node_id"])

        self.gateways: Dict[str, NodeGateway] = {}
        self.keypairs: Dict[str, Any] = {}
        self._last_rotation: Optional[dict] = None
        self.authority.register_revocation_callback(self._broadcast_revocation)
        self.ledger.register_sink(self._on_ledger_entry)

    def _on_watchdog_revocation(self, actor: str) -> None:
        if self.authority.get_node(actor) is not None and not self.authority.is_revoked(actor):
            self.authority.revoke_node(actor, reason="watchdog-automated-containment")

    def _broadcast_revocation(self, notice: RevocationNotice) -> None:
        authority_pub = self.authority.get_authority_public_key_bytes()
        with self._lock:
            gateways = list(self.gateways.values())
        for gw in gateways:
            gw.apply_revocation(notice, authority_pub)
        self.detector.add_revoked_node(notice.node_id)
        self.ledger.log(
            actor="Authority",
            action="REVOCATION_BROADCAST",
            target=notice.node_id,
            details={
                "revocation_epoch": notice.revocation_epoch,
                "reason": notice.reason,
                "notified_nodes": len(gateways),
            },
        )

    def _on_ledger_entry(self, entry) -> None:
        if entry.action in ("MESSAGE_SEND", "HANDSHAKE_INIT"):
            source = entry.actor
            target = entry.target
            if source in self.gateways and target in self.gateways:
                ev = LogEvent(
                    event_id=f"log-{entry.entry_id}",
                    timestamp=entry.timestamp,
                    received_at=time.time(),
                    actor=source,
                    action=entry.action,
                    source_service=source,
                    target_service=target,
                    key_epoch=self.authority.current_epoch,
                    details=entry.details,
                )
                self.detector.ingest_event(ev)
        elif entry.action == "REPLAY_DETECTED":
            ev = LogEvent(
                event_id=f"log-{entry.entry_id}",
                timestamp=entry.timestamp,
                received_at=time.time(),
                actor=entry.target,
                action=entry.action,
                source_service=entry.target,
                target_service=entry.actor,
                key_epoch=self.authority.current_epoch,
                details=entry.details,
            )
            self.detector.ingest_event(ev)

    def _install_node_gateway(self, node_id: str, kp: Any, pub: dict) -> NodeGateway:
        priv = serialize_private_keys(kp)
        gw = NodeGateway(
            node_id=node_id,
            keypair_private_key_bytes=priv,
            authority_client=self.authority,
            ledger=self.ledger,
        )
        for rev in self.authority.list_revocations():
            gw._revoked_peers.add(rev["node_id"])
        peer_info = PeerInfo(
            node_id=node_id,
            signing_public_bytes=pub["signing_public"],
            kem_public_bytes=pub["kem_public"],
            x25519_public_bytes=pub["x25519_public"],
        )

        for existing_id, existing_gw in self.gateways.items():
            existing_gw.register_peer(peer_info)
            existing_pub = serialize_public_keys(self.keypairs[existing_id])
            gw.register_peer(
                PeerInfo(
                    node_id=existing_id,
                    signing_public_bytes=existing_pub["signing_public"],
                    kem_public_bytes=existing_pub["kem_public"],
                    x25519_public_bytes=existing_pub["x25519_public"],
                )
            )

        self.keypairs[node_id] = kp
        self.gateways[node_id] = gw
        return gw

    def register_service_node(self, node_id: str) -> NodeGateway:
        """Provision hybrid PQC identity keys, register with Authority, and mesh peer keys."""
        with self._lock:
            if node_id in self.gateways:
                return self.gateways[node_id]

            kp = generate_identity_keypair(node_id)
            pub = serialize_public_keys(kp)

            if self.authority.get_node(node_id) is None:
                self.authority.register_node(
                    node_id=node_id,
                    signing_public_bytes=pub["signing_public"],
                    kem_public_bytes=pub["kem_public"],
                    x25519_public_bytes=pub["x25519_public"],
                )

            gw = self._install_node_gateway(node_id, kp, pub)
            self.ledger.log(
                actor="Authority",
                action="NODE_REGISTERED",
                target=node_id,
                details={"epoch": self.authority.current_epoch},
            )
            return gw

    def re_enroll_service_node(self, previous_node_id: str, new_node_id: str) -> dict:
        """Issue replacement PQC credentials for a revoked service while keeping old keys blocked."""
        with self._lock:
            if new_node_id in self.gateways or self.authority.get_node(new_node_id) is not None:
                raise ValueError(f"Replacement node '{new_node_id}' is already registered.")

            kp = generate_identity_keypair(new_node_id)
            pub = serialize_public_keys(kp)
            rec = self.authority.re_enroll_node(
                new_node_id=new_node_id,
                signing_public_bytes=pub["signing_public"],
                kem_public_bytes=pub["kem_public"],
                x25519_public_bytes=pub["x25519_public"],
                previous_node_id=previous_node_id,
            )
            self._install_node_gateway(new_node_id, kp, pub)
            self.ledger.log(
                actor="Authority",
                action="NODE_RE_ENROLLED",
                target=new_node_id,
                details={"previous_node_id": previous_node_id, "epoch": rec.key_epoch},
            )
            return {
                "node_id": rec.node_id,
                "previous_node_id": previous_node_id,
                "key_epoch": rec.key_epoch,
                "registered_at": rec.registered_at,
            }

    def provision_default_topology(self) -> List[str]:
        """Provision the standard enterprise service nodes defined in policy."""
        for name in DEFAULT_TOPOLOGY_SERVICES:
            self.register_service_node(name)
        return list(DEFAULT_TOPOLOGY_SERVICES)

    def send_encrypted_transfer(
        self, source_node: str, target_node: str, payload: bytes
    ) -> dict:
        """Establish a forward-secret hybrid session and deliver encrypted chunks end-to-end."""
        if source_node not in self.gateways or target_node not in self.gateways:
            raise ValueError("Both source and target service nodes must be registered.")

        src_gw = self.gateways[source_node]
        dst_gw = self.gateways[target_node]
        epoch = self.authority.current_epoch

        kem_ct, eph_pub, sig, sid_src = src_gw.initiate_handshake(target_node, epoch)
        sid_dst = dst_gw.complete_handshake(source_node, kem_ct, eph_pub, sig, epoch)

        transfer = src_gw.send_message(sid_src, payload, target_node)
        if not transfer.success:
            raise RuntimeError(transfer.error or "Transfer encryption failed")

        reassembled = None
        for chunk in transfer.encrypted_chunks:  # type: ignore[attr-defined]
            res = dst_gw.receive_chunk(
                sid_dst,
                chunk["nonce"],
                chunk["ciphertext"],
                chunk["aad"],
                chunk["seq_num"],
            )
            if res is not None:
                reassembled = res

        return {
            "msg_id": transfer.msg_id,
            "session_id": sid_src.hex(),
            "epoch": epoch,
            "chunks_sent": transfer.chunks_sent,
            "delivery_ms": round(transfer.delivery_ms, 3),
            "verified_match": reassembled == payload,
            "bytes_delivered": len(reassembled) if reassembled is not None else 0,
        }

    def rotate_epoch(self) -> dict:
        """Rotate the active cryptographic epoch and record the event in the audit ledger."""
        ep = self.authority.rotate_keys()
        rotation_info = {
            "epoch": ep.epoch,
            "valid_from": ep.valid_from,
            "grace_until": ep.grace_until,
            "cutoff": ep.cutoff,
        }
        self._last_rotation = rotation_info
        self.ledger.log(
            actor="Authority",
            action="KEY_ROTATE",
            target=f"Epoch-{ep.epoch}",
            details={
                "epoch": ep.epoch,
                "grace_until": ep.grace_until,
                "cutoff": ep.cutoff,
            },
        )
        return rotation_info

    def revoke_node(self, node_id: str, reason: str = "operator-triggered") -> dict:
        """Revoke `node_id` across all nodes and return propagation telemetry."""
        notice = self.authority.revoke_node(node_id, reason=reason)
        stats = self.authority.get_propagation_stats(notice.revocation_epoch)
        return {
            "node_id": notice.node_id,
            "revocation_epoch": notice.revocation_epoch,
            "revoked_at": notice.revoked_at,
            "reason": notice.reason,
            "propagation": stats,
        }

    def ingest_service_event(
        self,
        actor: str,
        action: str,
        source_service: str,
        target_service: str,
        timestamp: Optional[float] = None,
        flush_immediately: bool = False,
        details: Optional[dict] = None,
    ) -> List[dict]:
        """Log a service event and evaluate it through WatchdogDetector."""
        ts = timestamp if timestamp is not None else time.time()
        entry = self.ledger.log(
            actor=actor,
            action=action,
            target=target_service,
            details={"source_service": source_service, **(details or {})},
        )
        ev = LogEvent(
            event_id=f"ev-{entry.entry_id}-{secrets.token_hex(3)}",
            timestamp=ts,
            received_at=time.time(),
            actor=actor,
            action=action,
            source_service=source_service,
            target_service=target_service,
            key_epoch=self.authority.current_epoch,
            details=details or {},
        )
        alerts = list(self.detector.ingest_event(ev))
        if flush_immediately:
            alerts.extend(self.detector.flush())
        return [self._serialize_alert(a) for a in alerts]

    def backup_authority(self, filename: Optional[str] = None) -> dict:
        """Create an encrypted, ML-DSA-65 signed backup of the authority key material."""
        name = filename or f"authority-backup-{int(time.time())}.qvbak"
        path = str(Path(self.config.backup_dir) / name)
        info = self.authority.backup_keys(path)
        self.ledger.log(
            actor="Authority",
            action="KEY_BACKUP",
            target=info["path"],
            details={"checksum": info["checksum"], "size": info["size"]},
        )
        return info

    def list_backups(self) -> List[dict]:
        """List encrypted authority backups present in the configured backup directory."""
        root = Path(self.config.backup_dir)
        if not root.exists():
            return []
        files = sorted(root.glob("*.qvbak"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [
            {
                "name": p.name,
                "path": str(p),
                "size": p.stat().st_size,
                "modified_at": p.stat().st_mtime,
            }
            for p in files[:15]
        ]

    def get_epoch_status(self, query_epoch: Optional[int] = None, offset_seconds: float = 0.0) -> dict:
        """Evaluate current epoch, prior-epoch grace validity, or custom epoch timing."""
        current = self.authority.current_epoch
        target = current if query_epoch is None else query_epoch
        check_ts = time.time() + offset_seconds
        prior = current - 1 if current > 0 else None
        rot = self._last_rotation
        return {
            "query_epoch": target,
            "offset_seconds": offset_seconds,
            "is_valid": self.authority.is_epoch_valid(target, check_time=check_ts),
            "current_epoch": current,
            "prior_epoch": prior,
            "prior_epoch_valid": (
                self.authority.is_epoch_valid(prior, check_time=check_ts)
                if prior is not None
                else None
            ),
            "grace_period_seconds": self.config.grace_period_seconds,
            "valid_from": rot["valid_from"] if rot and rot["epoch"] == current else None,
            "grace_until": rot["grace_until"] if rot and rot["epoch"] == current else None,
        }

    def probe_replay_rejection(self, source_node: str = "WebPortal", target_node: str = "Auth") -> dict:
        """Execute a live session transfer and replay its packet to verify bitmask rejection."""
        if source_node not in self.gateways or target_node not in self.gateways:
            raise ValueError("Both source and target service nodes must be registered.")
        src_gw = self.gateways[source_node]
        dst_gw = self.gateways[target_node]
        epoch = self.authority.current_epoch

        kem_ct, eph_pub, sig, sid_src = src_gw.initiate_handshake(target_node, epoch)
        sid_dst = dst_gw.complete_handshake(source_node, kem_ct, eph_pub, sig, epoch)
        payload = b"Q-Vault replay-detection payload"
        tx = src_gw.send_message(sid_src, payload, target_node)
        if not tx.success:
            raise RuntimeError(tx.error or "Transfer setup failed")
        chunk = tx.encrypted_chunks[0]  # type: ignore[attr-defined]

        first = dst_gw.receive_chunk(
            sid_dst, chunk["nonce"], chunk["ciphertext"], chunk["aad"], chunk["seq_num"]
        )
        replay = dst_gw.receive_chunk(
            sid_dst, chunk["nonce"], chunk["ciphertext"], chunk["aad"], chunk["seq_num"]
        )
        flushed = [self._serialize_alert(a) for a in self.detector.flush()]
        return {
            "session_id": sid_src.hex()[:16],
            "seq_num": chunk["seq_num"],
            "first_delivery_bytes": len(first) if first is not None else 0,
            "replay_blocked": replay is None,
            "alerts_emitted": flushed,
        }

    def probe_aad_tampering(
        self,
        source_node: str = "WebPortal",
        target_node: str = "Auth",
        spoofed_recipient: str = "PayrollDB",
    ) -> dict:
        """Encrypt a chunk bound to `target_node` and verify `InvalidTag` when recipient is altered."""
        if source_node not in self.keypairs or target_node not in self.keypairs:
            raise ValueError("Both source and target service nodes must be registered.")
        kp_src = self.keypairs[source_node]
        kp_dst = self.keypairs[target_node]
        x_dst_pub = serialize_public_keys(kp_dst)["x25519_public"]
        epoch = self.authority.current_epoch

        hs_a, kem_ct, eph_pub, sig = perform_handshake_initiator(
            kp_src, kp_dst.kem_public, kp_dst.signing_public, x_dst_pub, target_node, epoch
        )
        hs_b = perform_handshake_responder(
            kp_dst, kem_ct, eph_pub, kp_src.signing_public, source_node, sig, epoch
        )
        chunk = encrypt_chunk(
            hs_a.session_keys,
            b"AAD recipient binding payload",
            f"aad-{secrets.token_hex(4)}",
            0,
            1,
            1,
            source_node,
            target_node,
        )
        rejected = False
        error_type = ""
        try:
            decrypt_chunk(hs_b.session_keys, chunk, source_node, spoofed_recipient)
        except InvalidTag:
            rejected = True
            error_type = "InvalidTag"

        self.ledger.log(
            actor=source_node,
            action="AAD_TAMPER_BLOCKED",
            target=spoofed_recipient,
            details={"intended_recipient": target_node, "exception": error_type},
        )
        return {
            "source_node": source_node,
            "intended_recipient": target_node,
            "spoofed_recipient": spoofed_recipient,
            "rejected": rejected,
            "exception": error_type,
        }

    def probe_resumption_hijack(
        self,
        authorized_peer: str = "WebPortal",
        host_node: str = "Auth",
        impersonator_peer: str = "PayrollDB",
    ) -> dict:
        """Issue a resumption ticket and verify hijack blocking, valid rotation, and replay block."""
        if authorized_peer not in self.gateways or host_node not in self.gateways:
            raise ValueError("Authorized peer and host service node must be registered.")
        peer_gw = self.gateways[authorized_peer]
        host_gw = self.gateways[host_node]
        epoch = self.authority.current_epoch

        kem_ct, eph_pub, sig, _ = peer_gw.initiate_handshake(host_node, epoch)
        sid_host = host_gw.complete_handshake(authorized_peer, kem_ct, eph_pub, sig, epoch)
        ticket = host_gw.create_resumption_ticket(sid_host)

        hijack_sid = host_gw.resume_session(ticket, impersonator_peer)
        valid_sid = host_gw.resume_session(ticket, authorized_peer)
        replay_sid = host_gw.resume_session(ticket, authorized_peer)

        self.ledger.log(
            actor=impersonator_peer,
            action="RESUMPTION_HIJACK_BLOCKED",
            target=host_node,
            details={"authorized_peer": authorized_peer, "rotated_session": valid_sid is not None},
        )
        return {
            "authorized_peer": authorized_peer,
            "host_node": host_node,
            "impersonator_peer": impersonator_peer,
            "hijack_blocked": hijack_sid is None,
            "valid_resumed": valid_sid is not None and valid_sid != sid_host,
            "rotated_session_id": valid_sid.hex()[:16] if valid_sid else None,
            "ticket_replay_blocked": replay_sid is None,
        }

    def probe_backup_tamper(self) -> dict:
        """Export an encrypted backup, verify clean restore, and verify 1-byte tamper rejection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ok_path = str(Path(tmpdir) / "intact.qvbak")
            bad_path = str(Path(tmpdir) / "tampered.qvbak")
            info = self.authority.backup_keys(ok_path)
            intact_restored = self.authority.restore_from_backup(ok_path)

            raw = bytearray(Path(ok_path).read_bytes())
            flip_offset = min(60, len(raw) - 1)
            raw[flip_offset] ^= 0x01
            Path(bad_path).write_bytes(bytes(raw))

            corrupted_rejected = False
            error_detail = ""
            try:
                self.authority.restore_from_backup(bad_path)
            except ValueError as exc:
                corrupted_rejected = True
                error_detail = str(exc)

            self.ledger.log(
                actor="Authority",
                action="BACKUP_TAMPER_VERIFIED",
                target="AuthorityDB",
                details={"byte_flipped": flip_offset, "rejected": corrupted_rejected},
            )
            return {
                "original_bytes": info["size"],
                "flipped_byte_offset": flip_offset,
                "intact_restored": intact_restored,
                "corrupted_rejected": corrupted_rejected,
                "error_detail": error_detail,
            }

    def probe_clock_skew(self) -> dict:
        """Feed out-of-order telemetry within the skew tolerance window and verify flush flagging."""
        now = time.time() - 1.5
        ev_later = LogEvent(
            event_id=f"skew-later-{secrets.token_hex(3)}",
            timestamp=now + 1.2,
            received_at=time.time(),
            actor="SkewedWorker",
            action="SERVICE_CALL",
            source_service="UserDB",
            target_service="PayrollDB",
            key_epoch=self.authority.current_epoch,
        )
        ev_earlier = LogEvent(
            event_id=f"skew-earlier-{secrets.token_hex(3)}",
            timestamp=now + 0.1,
            received_at=time.time(),
            actor="SkewedWorker",
            action="READ",
            source_service="WebPortal",
            target_service="Auth",
            key_epoch=self.authority.current_epoch,
        )
        before_flush = len(self.detector.ingest_event(ev_later)) + len(
            self.detector.ingest_event(ev_earlier)
        )
        flushed = [self._serialize_alert(a) for a in self.detector.flush()]
        self.ledger.log(
            actor="Watchdog",
            action="CLOCK_SKEW_VERIFIED",
            target="SkewedWorker",
            details={"buffered_immediately": before_flush, "flushed_alerts": len(flushed)},
        )
        return {
            "clock_tolerance_seconds": self.config.clock_tolerance_seconds,
            "buffered_before_flush": before_flush,
            "flushed_alerts": flushed,
            "ordering_uncertain_flagged": any(a["ordering_uncertain"] for a in flushed),
        }

    def _serialize_alert(self, alert) -> dict:
        return {
            "alert_id": alert.alert_id,
            "alert_type": alert.alert_type.value,
            "severity": alert.severity.value,
            "actor": alert.actor,
            "description": alert.description,
            "event_ids": alert.event_ids,
            "violated_rule": alert.violated_rule,
            "services_involved": alert.services_involved,
            "detected_at": alert.detected_at,
            "ordering_uncertain": alert.ordering_uncertain,
            "auto_revoke_triggered": alert.auto_revoke_triggered,
            "violated_path": alert.violated_path,
        }

    def get_snapshot(self) -> dict:
        """Return a complete control-plane, telemetry, and detector snapshot."""
        nodes = [
            {
                "node_id": n.node_id,
                "key_epoch": n.key_epoch,
                "registered_at": n.registered_at,
                "is_revoked": n.is_revoked,
                "revoked_at": n.revoked_at,
                "signing_fp": hashlib.sha256(n.signing_public_bytes).hexdigest()[:16],
                "signing_fp_full": hashlib.sha256(n.signing_public_bytes).hexdigest(),
                "kem_fp": hashlib.sha256(n.kem_public_bytes).hexdigest()[:16],
                "kem_fp_full": hashlib.sha256(n.kem_public_bytes).hexdigest(),
            }
            for n in self.authority.list_nodes(include_revoked=True)
        ]
        alerts = [self._serialize_alert(a) for a in self.detector.get_alerts()]
        all_entries = self.ledger.get_entries(since_id=0, limit=5000)
        entries = [asdict(e) for e in all_entries[-50:]]
        verify_res = self.ledger.verify_chain()

        handshake_actions = {
            "NODE_REGISTERED",
            "NODE_RE_ENROLLED",
            "HANDSHAKE_INIT",
            "MESSAGE_SEND",
            "RESUMPTION_SUCCESS",
            "REPLAY_DETECTED",
            "AAD_TAMPER_BLOCKED",
            "RECEIVE_TAMPER_DETECTED",
            "RECEIVE_AAD_BINDING_MISMATCH",
            "RESUMPTION_HIJACK_BLOCKED",
            "RESUMPTION_REPLAY_REJECTED",
            "HANDSHAKE_SIG_FAIL",
            "SERVICE_CALL",
        }
        crypto_reject_actions = {
            "REPLAY_DETECTED",
            "AAD_TAMPER_BLOCKED",
            "RECEIVE_TAMPER_DETECTED",
            "RECEIVE_AAD_BINDING_MISMATCH",
            "RESUMPTION_HIJACK_BLOCKED",
            "RESUMPTION_REPLAY_REJECTED",
            "HANDSHAKE_SIG_FAIL",
        }
        handshakes_total = max(len(nodes), sum(1 for e in all_entries if e.action in handshake_actions))
        crypto_blocked = sum(1 for e in all_entries if e.action in crypto_reject_actions)
        aad_verified = max(0, handshakes_total - crypto_blocked)
        policy_blocked = min(aad_verified, len(alerts))
        policy_allowed = max(0, aad_verified - policy_blocked)
        ledger_anchored = policy_allowed if verify_res["ok"] else 0
        total_verified = verify_res["total_entries"]
        faults = len(verify_res["tampered_entries"]) + len(verify_res["bad_checkpoints"])
        chain_integrity_pct = 100.0 if verify_res["ok"] else round(100.0 * max(0, total_verified - faults) / max(1, total_verified), 1)

        return {
            "current_epoch": self.authority.current_epoch,
            "revocation_epoch": self.authority.revocation_epoch,
            "grace_period_seconds": self.config.grace_period_seconds,
            "clock_tolerance_seconds": self.config.clock_tolerance_seconds,
            "checkpoint_interval": self.config.checkpoint_interval,
            "epoch_status": self.get_epoch_status(),
            "nodes": nodes,
            "revocations": self.authority.list_revocations(),
            "recent_backups": self.list_backups(),
            "alerts": list(reversed(alerts[-50:])),
            "metrics": self.detector.get_metrics_report(),
            "service_graph": self.detector.get_service_graph_summary(),
            "ledger_summary": self.ledger.export_summary(),
            "chain_verified": verify_res["ok"],
            "chain_integrity_pct": chain_integrity_pct,
            "pipeline_stats": {
                "handshakes": handshakes_total,
                "aad_verified": aad_verified,
                "policy_allowed": policy_allowed,
                "ledger_anchored": ledger_anchored,
                "crypto_blocked": crypto_blocked,
                "policy_blocked": policy_blocked,
            },
            "recent_entries": list(reversed(entries)),
        }

    def close(self) -> None:
        self.authority.close()
