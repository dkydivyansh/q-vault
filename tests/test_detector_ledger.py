"""Tamper-evident ledger, clock-skew buffering, deterministic detection, and benchmark metrics tests."""

import json
import time

from src.sdk import (
    AlertType,
    AuditLedger,
    LogEvent,
    Severity,
    WatchdogDetector,
    generate_identity_keypair,
)

ALLOWED_PATHS = [
    ["WebPortal", "Auth"],
    ["WebPortal", "FileGateway"],
    ["Auth", "Billing"],
    ["Auth", "UserDB"],
    ["FileGateway", "VaultDB"],
    ["Billing", "PayrollDB"],
    ["Admin", "Auth"],
    ["Admin", "UserDB"],
]


def test_log_injection_escaped_as_single_json_line(tmp_path):
    kp = generate_identity_keypair("Ledger")
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(str(ledger_path), kp.signing_private, kp.signing_public, checkpoint_interval=5)

    injected_actor = 'alice\n{"actor":"admin","action":"grant"}'
    ledger.log(actor=injected_actor, action="LOGIN", target="WebPortal", details={})

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["actor"] == injected_actor


def test_log_chain_verification_and_tamper_detection(tmp_path):
    kp = generate_identity_keypair("Ledger")
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(str(ledger_path), kp.signing_private, kp.signing_public, checkpoint_interval=3)

    for i in range(6):
        ledger.log(actor="NodeA", action=f"ACT_{i}", target="Auth", details={"i": i})

    valid_res = ledger.verify_chain()
    assert valid_res["ok"] is True
    assert valid_res["total_entries"] == 6

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    mutated = json.loads(lines[1])
    mutated["actor"] = "MaliciousAdmin"
    lines[1] = json.dumps(mutated, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tamper_res = ledger.verify_chain()
    assert tamper_res["ok"] is False
    assert 1 in tamper_res["tampered_entries"]


def test_clock_skew_reorder_and_ordering_uncertain_flag():
    detector = WatchdogDetector(allowed_paths=ALLOWED_PATHS, clock_tolerance=5.0)
    base = time.time() - 2.0

    # Events arrive out of timestamp order within the 5-second skew buffer.
    ev_late = LogEvent("e2", base + 1.5, time.time(), "FileGateway", "ACCESS", "VaultDB", "PayrollDB", 1)
    ev_early = LogEvent("e1", base + 0.2, time.time(), "FileGateway", "ACCESS", "WebPortal", "FileGateway", 1)

    assert detector.ingest_event(ev_late) == []
    assert detector.ingest_event(ev_early) == []
    alerts = detector.flush()
    assert len(alerts) >= 1
    assert all(a.ordering_uncertain is True for a in alerts)
    assert alerts[0].event_ids == ["e2"]


def test_context_aware_privilege_escalation_rules():
    now = time.time() - 10.0
    detector = WatchdogDetector(
        allowed_paths=ALLOWED_PATHS,
        admin_nodes={"Admin"},
        maintenance_windows=[{"actor": "MaintUser", "start": now - 60.0, "end": now + 60.0}],
    )

    detector.ingest_event(LogEvent("e-admin", now, now, "Admin", "grant_role", "Admin", "Auth", 1))
    detector.ingest_event(LogEvent("e-maint", now + 1, now, "MaintUser", "sudo_patch", "Auth", "UserDB", 1))
    assert len(detector.get_alerts()) == 0

    alerts = detector.ingest_event(
        LogEvent("e-priv", now + 2, now, "RegularUser", "grant_admin", "Auth", "UserDB", 1)
    )
    assert any(a.alert_type == AlertType.PRIVILEGE_ESCALATION for a in alerts)


def test_lateral_movement_and_auto_revocation_callback():
    revoked_actors = []
    detector = WatchdogDetector(
        allowed_paths=ALLOWED_PATHS,
        lateral_window=60.0,
        lateral_max_hops=3,
        revocation_callback=lambda actor: revoked_actors.append(actor),
    )

    base = time.time() - 15.0
    events = [
        LogEvent("h1", base, base, "CompromisedNode", "CALL", "WebPortal", "FileGateway", 1),
        LogEvent("h2", base + 1.0, base, "CompromisedNode", "CALL", "FileGateway", "VaultDB", 1),
        LogEvent("h3", base + 2.0, base, "CompromisedNode", "CALL", "VaultDB", "PayrollDB", 1),
    ]
    all_alerts = []
    for ev in events:
        all_alerts.extend(detector.ingest_event(ev))

    critical_alerts = [
        a
        for a in all_alerts
        if a.alert_type == AlertType.LATERAL_MOVEMENT and a.severity == Severity.CRITICAL
    ]
    assert len(critical_alerts) >= 1
    lat_alert = critical_alerts[0]
    assert lat_alert.actor == "CompromisedNode"
    assert {"h1", "h2", "h3"}.issubset(set(lat_alert.event_ids))
    assert {"WebPortal", "FileGateway", "VaultDB", "PayrollDB"}.issubset(
        set(lat_alert.services_involved)
    )
    assert lat_alert.violated_rule == "LAT_MOVE_001"
    assert lat_alert.violated_path and "VaultDB->PayrollDB" in lat_alert.violated_path
    assert "CompromisedNode" in revoked_actors

    follow_up = detector.ingest_event(
        LogEvent("h4", base + 3.0, base, "CompromisedNode", "CALL", "WebPortal", "Auth", 1)
    )
    assert any(a.alert_type == AlertType.REVOKED_ACCESS_ATTEMPT for a in follow_up)


def test_benchmark_runner_produces_real_metrics():
    from src.app.benchmark import run_benchmark

    res = run_benchmark(
        handshake_iterations=5,
        chunk_iterations=10,
        benign_events=100,
        attack_events=12,
    )
    assert res["grace_period_seconds"] == 30.0
    assert res["handshake_ms"]["median"] > 0.0
    assert res["revocation_propagation_ms"]["nodes_acked"] == 8
    assert res["detection_benchmark"]["f1_score"] > 0.9
    assert res["detection_benchmark"]["fp_per_1000_benign"] == 0.0


def test_batch_evaluation_metrics_f1_tta_and_fp_per_1000():
    detector = WatchdogDetector(allowed_paths=ALLOWED_PATHS, clock_tolerance=5.0)
    base = time.time() - 30.0

    events = [
        LogEvent("b1", base + 0.0, base, "User1", "READ", "WebPortal", "Auth", 1),
        LogEvent("b2", base + 6.0, base, "User1", "READ", "Auth", "Billing", 1),
        LogEvent("a1", base + 12.0, base, "Attacker", "CALL", "VaultDB", "PayrollDB", 1),
        LogEvent("a2", base + 18.0, base, "Attacker", "grant_admin", "PayrollDB", "Admin", 1),
    ]
    ground_truth = {"b1": False, "b2": False, "a1": True, "a2": True}

    metrics = detector.run_batch_evaluation(events, ground_truth)
    assert metrics.f1_score() > 0.99
    assert metrics.fp_per_1000() == 0.0
    assert metrics.median_tta() >= 0.0
    report = detector.get_metrics_report()
    assert report["f1_score"] > 0.99
