# Audit Ledger & Watchdog Detector API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. `AuditLedger` — Tamper-Evident Telemetry Store

`AuditLedger` appends every security action as one canonical JSON line (`sort_keys=True, ensure_ascii=True, separators=(",", ":")`) linked sequentially via `SHA-256` (`GENESIS_HASH = "0" * 64`), synchronized to disk with `flush()` + `os.fsync()`, and signed periodically every `checkpoint_interval` records using `ML-DSA-65` under `CTX_LOG`.

### Constants & Dataclass

* `GENESIS_HASH`: `"0" * 64`
* `DEFAULT_CHECKPOINT_INTERVAL`: `100`
* **`LogEntry`:**
  * `entry_id: int` — Zero-based monotonic log index.
  * `timestamp: float` — Unix timestamp assigned when `log()` commits.
  * `actor: str`, `action: str`, `target: str`, `details: dict` — Canonicalized event attributes (`\n` and `\r` control chars escaped inside JSON).
  * `prev_hash: str` — 64-char hex `SHA-256` of preceding record (`GENESIS_HASH` for entry `0`).
  * `entry_hash: str` — `SHA-256(prev_hash || canonical_partial_json)`.
  * `is_checkpoint: bool = False` — `True` when `entry_id > 0` and `entry_id % checkpoint_interval == 0`.
  * `checkpoint_signature: Optional[str] = None` — Hex-encoded `ML-DSA-65` signature over `entry_hash` (`None` / `null` on intermediate chained records).

### Constructor & Methods

```python
from src.sdk import AuditLedger

ledger = AuditLedger(
    ledger_path: str,
    signing_key: MLDSA65PrivateKey,
    verify_key: MLDSA65PublicKey,
    checkpoint_interval: int = 100,
)
```

| Method & Signature | Parameters | Return Value & Behavior |
| :--- | :--- | :--- |
| `log(actor, action, target, details=None)` | `actor: str`, `action: str`, `target: str`, `details: Optional[dict]` | Writes one canonical JSON line, invokes `flush()` and `os.fsync()`, triggers sinks outside the lock, returns `LogEntry`. |
| `verify_chain()` | — | Re-computes every `SHA-256` hash link and verifies all checkpoint `ML-DSA-65` signatures. Returns `{"ok": bool, "total_entries": int, "tampered_entries": list[int], "bad_checkpoints": list[int], "message": str}`. |
| `get_entries(since_id=0, limit=100)` | `since_id: int`, `limit: int` | Reads up to `limit` entries with `entry_id >= since_id`. |
| `export_summary()` | — | Returns `{"total_entries": int, "current_chain_head": str, "ledger_path": str}`. |
| `register_sink(callback)` | `Callable[[LogEntry], None]` | Subscribes a downstream listener (e.g. forwarding entries into `WatchdogDetector`). |

#### Example: Injection Resistance & Hash-Chain Verification

```python
import json
import tempfile
from pathlib import Path
from src.sdk import AuditLedger, generate_identity_keypair

with tempfile.TemporaryDirectory() as tmp:
    kp = generate_identity_keypair("LedgerSigner")
    log_file = Path(tmp) / "audit.jsonl"
    ledger = AuditLedger(str(log_file), kp.signing_private, kp.signing_public, checkpoint_interval=3)

    # Newlines inside actor input are escaped onto one canonical JSON line
    ledger.log(actor='mallory\n{"actor":"admin","action":"GRANT"}', action="LOGIN", target="WebPortal")
    for i in range(4):
        ledger.log(actor="WebPortal", action="READ", target="Auth", details={"seq": i})

    assert len(log_file.read_text(encoding="utf-8").splitlines()) == 5
    assert ledger.verify_chain()["ok"] is True

    # Mutating entry 1 fails chain verification
    lines = log_file.read_text(encoding="utf-8").splitlines()
    mutated = json.loads(lines[1])
    mutated["target"] = "PayrollDB"
    lines[1] = json.dumps(mutated, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ledger.verify_chain()
    assert res["ok"] is False and 1 in res["tampered_entries"]
```

---

## 2. `WatchdogDetector` — Deterministic Zero-AI Detection & Auto-Revocation

`WatchdogDetector` combines three pure-Python deterministic components (`ClockSkewBuffer`, `ServiceAccessGraph`, `RuleEngine`) plus labeled evaluation reporting (`DetectionMetrics`) and automatic revocation triggers.

### Enumerations & Dataclasses

* **`Severity(Enum)`:** `LOW` (`"low"`, score `0.3`), `MEDIUM` (`"medium"`, `0.5`), `HIGH` (`"high"`, `0.75`), `CRITICAL` (`"critical"`, `1.0`).
* **`AlertType(Enum)`:**
  * `PRIVILEGE_ESCALATION = "PRIV_ESC_001"`
  * `LATERAL_MOVEMENT = "LAT_MOVE_001"`
  * `REPLAY_ATTACK = "REPLAY_001"`
  * `CLOCK_SKEW_EXCEEDED = "CLOCK_001"`
  * `REVOKED_ACCESS_ATTEMPT = "REVOKED_001"`
  * `RAPID_SERVICE_HOP = "HOP_001"`
* **`LogEvent`:** `(event_id: str, timestamp: float, received_at: float, actor: str, action: str, source_service: str, target_service: str, key_epoch: int, details: dict = {}, ordering_uncertain: bool = False)`
* **`Alert`:** `(alert_id: str, alert_type: AlertType, severity: Severity, actor: str, description: str, event_ids: List[str], violated_rule: str, services_involved: List[str], detected_at: float, ordering_uncertain: bool = False, auto_revoke_triggered: bool = False, violated_path: Optional[str] = None)`
* **`DetectionMetrics`:**
  * Fields: `true_positives: int`, `false_positives: int`, `false_negatives: int`, `true_negatives: int`, `time_to_alert_seconds: List[float]`, `total_benign_events: int`.
  * `f1_score() -> float` — Harmonic mean of precision and recall.
  * `median_tta() -> float` — Median detection latency (seconds) across true-positive alerts.
  * `fp_per_1000() -> float` — `(false_positives / total_benign_events) * 1000`.

### Constructor & Methods

```python
from src.sdk import WatchdogDetector

detector = WatchdogDetector(
    allowed_paths: List[List[str]],
    clock_tolerance: float = 5.0,
    lateral_window: float = 60.0,
    lateral_max_hops: int = 3,
    critical_threshold: float = 0.85,
    revocation_callback: Optional[Callable[[str], None]] = None,
    admin_nodes: Set[str] = None,
    maintenance_windows: List[dict] = None,
)
```

| Parameter / Method | Description & Return Value |
| :--- | :--- |
| `allowed_paths` | Permitted `[source, target]` directed edges (e.g., `[["WebPortal", "Auth"], ["FileGateway", "VaultDB"]]`). Intra-service calls (`src == dst`) are always allowed. |
| `clock_tolerance` | Buffering window (`±5.0s` default) sorting late/unordered telemetry; adjacent settled events within tolerance are flagged `ordering_uncertain=True`. |
| `lateral_window` & `lateral_max_hops` | If an actor makes `>= lateral_max_hops` transitions inside `lateral_window` seconds involving at least one unauthorized edge, emits `CRITICAL` `LAT_MOVE_001`. |
| `critical_threshold` & `revocation_callback` | Alerts whose severity score meets `critical_threshold` (`0.85` -> `CRITICAL`) invoke `revocation_callback(alert.actor)` and mark `actor` revoked. |
| `admin_nodes` & `maintenance_windows` | Actor set (`{"Admin"}`) and `[{"actor": str, "start": float, "end": float}]` intervals exempted from routine `PRIV_ESC_001` escalation alerts. |
| `ingest_event(event: LogEvent) -> List[Alert]` | Inserts event into `ClockSkewBuffer` and returns alerts from events settled past `clock_tolerance`. |
| `flush() -> List[Alert]` | Drains remaining buffered events sorted by `timestamp` and evaluates them immediately. |
| `add_revoked_node(node_id: str) -> None` | Marks `node_id` revoked so any future activity emits `CRITICAL` `REVOKED_001`. |
| `get_alerts(since: float = 0.0) -> List[Alert]` | Returns stored alerts with `detected_at >= since`. |
| `run_batch_evaluation(events, ground_truth) -> DetectionMetrics` | Evaluates `events` against `{event_id: bool}` ground truth, auto-flushes, updates metrics, and returns `DetectionMetrics`. |
| `get_metrics_report() -> dict` | Returns `{"f1_score", "median_tta_seconds", "fp_per_1000_events", "total_alerts", "critical_alerts", "auto_revocations"}`. |
| `get_service_graph_summary() -> dict` | Returns `{"allowed_paths": list, "actor_access_history": dict}` (latest 20 hops per actor). |

#### Example: Clock Skew, Context-Aware Rules, Lateral Movement & Batch Metrics

```python
import time
from src.sdk import AlertType, LogEvent, Severity, WatchdogDetector

allowed = [["WebPortal", "Auth"], ["WebPortal", "FileGateway"], ["FileGateway", "VaultDB"], ["Admin", "Auth"]]
revoked = []
now = time.time() - 10.0

detector = WatchdogDetector(
    allowed_paths=allowed,
    clock_tolerance=5.0,
    lateral_window=60.0,
    lateral_max_hops=3,
    revocation_callback=lambda actor: revoked.append(actor),
    admin_nodes={"Admin"},
    maintenance_windows=[{"actor": "MaintBot", "start": now - 60.0, "end": now + 60.0}],
)

# 1. Authorized admin & maintenance actions generate zero false alerts
detector.ingest_event(LogEvent("b1", now, now, "Admin", "grant_role", "Admin", "Auth", 0))
detector.ingest_event(LogEvent("b2", now + 1, now, "MaintBot", "sudo_patch", "WebPortal", "Auth", 0))

# 2. Lateral movement across unauthorized hops auto-triggers revocation callback
detector.ingest_event(LogEvent("a1", now + 2, now, "RogueNode", "CALL", "WebPortal", "FileGateway", 0))
detector.ingest_event(LogEvent("a2", now + 3, now, "RogueNode", "CALL", "FileGateway", "VaultDB", 0))
detector.ingest_event(LogEvent("a3", now + 4, now, "RogueNode", "CALL", "VaultDB", "PayrollDB", 0))

detector.flush()
alerts = detector.get_alerts()
assert any(a.alert_type == AlertType.LATERAL_MOVEMENT and a.severity == Severity.CRITICAL for a in alerts)
assert "RogueNode" in revoked
```

### Lower-Level Building Blocks

Each stage of `WatchdogDetector` can also be imported directly from `src.sdk`:
* **`ClockSkewBuffer(tolerance_seconds=5.0, max_buffer_size=10_000)`** — `ingest(event) -> List[LogEvent]`, `flush() -> List[LogEvent]`.
* **`ServiceAccessGraph(allowed_paths)`** — `is_path_allowed(source, target) -> bool`, `record_access(actor, source, target, timestamp, event_id="")`, `check_lateral_movement(...) -> Optional[dict]`, `check_unauthorized_path(actor, source, target) -> bool`, `get_summary() -> dict`.
* **`RuleEngine(admin_nodes=None, maintenance_windows=None)`** — `is_in_maintenance_window(actor, check_time) -> bool`, `check_privilege_escalation(event) -> Optional[Alert]`, `check_revoked_access(event, revoked_nodes) -> Optional[Alert]`, `check_replay_event(event) -> Optional[Alert]`.
