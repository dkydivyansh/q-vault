"""Closed-loop orchestrator uniting KeyAuthority, NodeGateways, AuditLedger, and WatchdogDetector."""

import hashlib
import secrets
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.sdk import (
    AuditLedger,
    KeyAuthority,
    LogEvent,
    NodeGateway,
    PeerInfo,
    RevocationNotice,
    WatchdogDetector,
    generate_identity_keypair,
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

    def register_service_node(self, node_id: str) -> NodeGateway:
        """Provision hybrid PQC identity keys, register with Authority, and mesh peer keys."""
        with self._lock:
            if node_id in self.gateways:
                return self.gateways[node_id]

            kp = generate_identity_keypair(node_id)
            pub = serialize_public_keys(kp)
            priv = serialize_private_keys(kp)

            if self.authority.get_node(node_id) is None:
                self.authority.register_node(
                    node_id=node_id,
                    signing_public_bytes=pub["signing_public"],
                    kem_public_bytes=pub["kem_public"],
                    x25519_public_bytes=pub["x25519_public"],
                )

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
            self.ledger.log(
                actor="Authority",
                action="NODE_REGISTERED",
                target=node_id,
                details={"epoch": self.authority.current_epoch},
            )
            return gw

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
        return {
            "epoch": ep.epoch,
            "valid_from": ep.valid_from,
            "grace_until": ep.grace_until,
            "cutoff": ep.cutoff,
        }

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
                "kem_fp": hashlib.sha256(n.kem_public_bytes).hexdigest()[:16],
            }
            for n in self.authority.list_nodes(include_revoked=True)
        ]
        alerts = [self._serialize_alert(a) for a in self.detector.get_alerts()]
        entries = [asdict(e) for e in self.ledger.get_entries(since_id=max(0, self.ledger._entry_count - 25), limit=25)]
        return {
            "current_epoch": self.authority.current_epoch,
            "revocation_epoch": self.authority.revocation_epoch,
            "grace_period_seconds": self.config.grace_period_seconds,
            "clock_tolerance_seconds": self.config.clock_tolerance_seconds,
            "nodes": nodes,
            "revocations": self.authority.list_revocations(),
            "alerts": list(reversed(alerts[-50:])),
            "metrics": self.detector.get_metrics_report(),
            "service_graph": self.detector.get_service_graph_summary(),
            "ledger_summary": self.ledger.export_summary(),
            "recent_entries": list(reversed(entries)),
        }

    def close(self) -> None:
        self.authority.close()
