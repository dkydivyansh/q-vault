"""Deterministic performance, revocation latency, and detection benchmark runner."""

import secrets
import statistics
import tempfile
import time
from pathlib import Path
from typing import Dict, List

from src.sdk import (
    AuditLedger,
    KeyAuthority,
    LogEvent,
    NodeGateway,
    PeerInfo,
    WatchdogDetector,
    generate_identity_keypair,
    serialize_private_keys,
    serialize_public_keys,
)

from .config import DEFAULT_ALLOWED_PATHS


def run_benchmark(
    handshake_iterations: int = 20,
    chunk_iterations: int = 50,
    benign_events: int = 1000,
    attack_events: int = 50,
) -> dict:
    """Measure PQC handshake, AES-GCM overhead, revocation latency, ledger speed, and detection metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        kek = secrets.token_hex(32)
        auth = KeyAuthority(str(tmp / "bench_auth.db"), kek, grace_period_seconds=30.0)

        services = [
            "WebPortal",
            "Auth",
            "FileGateway",
            "Billing",
            "UserDB",
            "VaultDB",
            "PayrollDB",
            "Admin",
        ]
        gateways: Dict[str, NodeGateway] = {}
        peers: List[PeerInfo] = []
        for svc in services:
            kp = generate_identity_keypair(svc)
            pub = serialize_public_keys(kp)
            priv = serialize_private_keys(kp)
            auth.register_node(svc, pub["signing_public"], pub["kem_public"], pub["x25519_public"])
            gateways[svc] = NodeGateway(svc, priv, authority_client=auth)
            peers.append(PeerInfo(svc, pub["signing_public"], pub["kem_public"], pub["x25519_public"]))

        for gw in gateways.values():
            for p in peers:
                if p.node_id != gw.node_id:
                    gw.register_peer(p)

        auth_pub = auth.get_authority_public_key_bytes()
        auth.register_revocation_callback(
            lambda notice: [g.apply_revocation(notice, auth_pub) for g in gateways.values()]
        )

        # Hybrid handshake timing
        hs_times_ms: List[float] = []
        last_sid = b""
        for _ in range(handshake_iterations):
            t0 = time.perf_counter()
            ct, eph, sig, sid_a = gateways["WebPortal"].initiate_handshake("Auth", epoch=0)
            sid_b = gateways["Auth"].complete_handshake("WebPortal", ct, eph, sig, epoch=0)
            t1 = time.perf_counter()
            assert sid_a == sid_b
            last_sid = sid_a
            hs_times_ms.append((t1 - t0) * 1000.0)

        # AES-256-GCM 64KB chunk encryption + decryption timing
        payload = secrets.token_bytes(65536)
        chunk_times_ms: List[float] = []
        for _ in range(chunk_iterations):
            t0 = time.perf_counter()
            tx = gateways["WebPortal"].send_message(last_sid, payload, "Auth")
            c = tx.encrypted_chunks[0]  # type: ignore[attr-defined]
            out = gateways["Auth"].receive_chunk(
                last_sid, c["nonce"], c["ciphertext"], c["aad"], c["seq_num"]
            )
            t1 = time.perf_counter()
            assert out == payload
            chunk_times_ms.append((t1 - t0) * 1000.0)

        total_mb = (len(payload) * chunk_iterations) / (1024.0 * 1024.0)
        total_chunk_s = sum(chunk_times_ms) / 1000.0

        # Cross-node revocation propagation across 8 service nodes
        notice = auth.revoke_node("FileGateway", reason="benchmark-containment")
        prop_stats = auth.get_propagation_stats(notice.revocation_epoch)

        # Ledger append + verification timing (200 entries, checkpoints every 50)
        ledger_key = auth.get_or_create_ledger_signing_key()
        ledger = AuditLedger(
            str(tmp / "bench_audit.jsonl"),
            ledger_key,
            ledger_key.public_key(),
            checkpoint_interval=50,
        )
        t_log_start = time.perf_counter()
        for i in range(200):
            ledger.log("WebPortal", "READ", "Auth", {"seq": i})
        t_log_end = time.perf_counter()

        t_ver_start = time.perf_counter()
        ver = ledger.verify_chain()
        t_ver_end = time.perf_counter()
        assert ver["ok"] is True

        # Deterministic detection benchmark (1,000 benign + 50 attack events)
        base = time.time() - 6.0
        detector = WatchdogDetector(
            allowed_paths=DEFAULT_ALLOWED_PATHS,
            clock_tolerance=5.0,
            lateral_window=60.0,
            lateral_max_hops=3,
            admin_nodes={"Admin"},
            maintenance_windows=[
                {"actor": "MaintSvc", "start": base - 10.0, "end": base + 3600.0}
            ],
        )

        events: List[LogEvent] = []
        ground_truth: Dict[str, bool] = {}

        benign_edges = [
            ("WebPortal", "Auth"),
            ("WebPortal", "FileGateway"),
            ("Auth", "Billing"),
            ("Auth", "UserDB"),
            ("FileGateway", "VaultDB"),
            ("Billing", "PayrollDB"),
        ]
        for i in range(benign_events):
            if i % 20 == 0:
                actor, action, src, dst = "Admin", "grant_role", "Admin", "Auth"
            elif i % 20 == 1:
                actor, action, src, dst = "MaintSvc", "sudo_upgrade", "Auth", "UserDB"
            else:
                src, dst = benign_edges[i % len(benign_edges)]
                actor, action = f"ServiceWorker-{i % 10}", "READ"
            eid = f"benign-{i}"
            events.append(
                LogEvent(
                    event_id=eid,
                    timestamp=base + (i * 0.001),
                    received_at=time.time(),
                    actor=actor,
                    action=action,
                    source_service=src,
                    target_service=dst,
                    key_epoch=0,
                )
            )
            ground_truth[eid] = False

        attack_edges = [
            ("VaultDB", "PayrollDB"),
            ("UserDB", "PayrollDB"),
            ("PayrollDB", "VaultDB"),
            ("WebPortal", "PayrollDB"),
        ]
        for j in range(attack_events):
            eid = f"attack-{j}"
            if j % 3 == 0:
                src, dst = attack_edges[j % len(attack_edges)]
                events.append(
                    LogEvent(
                        event_id=eid,
                        timestamp=base + 1.1 + (j * 0.01),
                        received_at=time.time(),
                        actor=f"Compromised-{j % 5}",
                        action="SERVICE_CALL",
                        source_service=src,
                        target_service=dst,
                        key_epoch=0,
                    )
                )
            elif j % 3 == 1:
                events.append(
                    LogEvent(
                        event_id=eid,
                        timestamp=base + 1.2 + (j * 0.01),
                        received_at=time.time(),
                        actor=f"StandardUser-{j % 5}",
                        action="grant_admin",
                        source_service="Auth",
                        target_service="UserDB",
                        key_epoch=0,
                    )
                )
            else:
                events.append(
                    LogEvent(
                        event_id=eid,
                        timestamp=base + 1.3 + (j * 0.01),
                        received_at=time.time(),
                        actor=f"ReplayActor-{j % 3}",
                        action="REPLAY_DETECTED",
                        source_service="WebPortal",
                        target_service="Auth",
                        key_epoch=0,
                    )
                )
            ground_truth[eid] = True

        t_det_start = time.perf_counter()
        metrics = detector.run_batch_evaluation(events, ground_truth)
        t_det_end = time.perf_counter()
        report = detector.get_metrics_report()
        alerts = detector.get_alerts()
        uncertain_count = sum(1 for a in alerts if a.ordering_uncertain)

        auth.close()

        return {
            "grace_period_seconds": 30.0,
            "handshake_ms": {
                "min": round(min(hs_times_ms), 3),
                "median": round(statistics.median(hs_times_ms), 3),
                "max": round(max(hs_times_ms), 3),
            },
            "aes_gcm_64kb_roundtrip": {
                "median_ms": round(statistics.median(chunk_times_ms), 3),
                "throughput_mb_s": round(total_mb / max(total_chunk_s, 1e-6), 2),
            },
            "revocation_propagation_ms": {
                "nodes_acked": prop_stats["total_acked"],
                "min": round(prop_stats["min_propagation_ms"], 3),
                "max": round(prop_stats["max_propagation_ms"], 3),
            },
            "ledger_200_entries": {
                "write_ms": round((t_log_end - t_log_start) * 1000.0, 2),
                "verify_ms": round((t_ver_end - t_ver_start) * 1000.0, 2),
            },
            "detection_benchmark": {
                "total_events": len(events),
                "benign_events": benign_events,
                "attack_events": attack_events,
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "false_negatives": metrics.false_negatives,
                "true_negatives": metrics.true_negatives,
                "f1_score": round(metrics.f1_score(), 4),
                "median_tta_seconds": round(metrics.median_tta(), 4),
                "batch_eval_ms": round((t_det_end - t_det_start) * 1000.0, 2),
                "fp_per_1000_benign": round(metrics.fp_per_1000(), 3),
                "ordering_uncertain_alerts": uncertain_count,
                "auto_revocations": report["auto_revocations"],
            },
        }
