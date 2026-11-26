# Audit Ledger & Watchdog Detector API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. `AuditLedger` & `LogEntry`

Append-only JSONL telemetry store enforcing canonical escaping (`ensure_ascii=True`, `sort_keys=True`), `SHA-256` hash chaining, and `ML-DSA-65` checkpoint signatures.

### `LogEntry` Dataclass

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `entry_id` | `int` | Required | Zero-based monotonic sequence index. |
| `timestamp` | `float` | Required | Unix timestamp recorded at `log()` invocation. |
| `actor` | `str` | Required | Identity initiating the logged event (escaped automatically). |
| `action` | `str` | Required | Machine-readable action token. |
| `target` | `str` | Required | Target service or resource. |
| `details` | `dict` | Required | Structured JSON-serializable metadata. |
| `prev_hash` | `str` | Required | `64`-char hex `SHA-256` of previous record (or `GENESIS_HASH`, `"0" * 64`). |
| `entry_hash` | `str` | Required | `64`-char hex `SHA-256(prev_hash || canonical_partial_json)`. |
| `is_checkpoint` | `bool` | `False` | `True` on every `checkpoint_interval`-th entry (`entry_id > 0`). |
| `checkpoint_signature` | `Optional[str]` | `None` | Hex-encoded `ML-DSA-65` signature over `entry_hash` under `CTX_LOG`. |

### `AuditLedger` Constructor & Methods

```python
AuditLedger(
    ledger_path: str,
    signing_key: MLDSA65PrivateKey,
    verify_key: MLDSA65PublicKey,
    checkpoint_interval: int = 100,
) -> None
```

| Method & Signature | Expected Inputs | Return Value / Output |
| :--- | :--- | :--- |
| `log(actor, action, target, details=None)` | `actor: str`, `action: str`, `target: str`, `details: Optional[dict]` | Committed `LogEntry` written with `flush()` + `os.fsync()` |
| `verify_chain()` | — | `{"ok": bool, "total_entries": int, "tampered_entries": list[int], "bad_checkpoints": list[int], "message": str}` |
| `get_entries(since_id=0, limit=100)` | `since_id: int`, `limit: int` | `List[LogEntry]` with `entry_id >= since_id` |
| `export_summary()` | — | `{"total_entries": int, "current_chain_head": str, "ledger_path": str}` |
| `register_sink(callback)` | `Callable[[LogEntry], None]` | `None`; callback invoked after durable commit |

---

## 2. `WatchdogDetector` & Supporting Components

Deterministic zero-AI detection engine combining clock-skew buffering, directed service-graph tracking, rule evaluation, and automated revocation.

### Enumerations & Dataclasses

* **`Severity`:** `LOW` (`"low"`), `MEDIUM` (`"medium"`), `HIGH` (`"high"`), `CRITICAL` (`"critical"`).
* **`AlertType`:**
  * `PRIVILEGE_ESCALATION` (`"PRIV_ESC_001"`)
  * `LATERAL_MOVEMENT` (`"LAT_MOVE_001"`)
  * `REPLAY_ATTACK` (`"REPLAY_001"`)
  * `CLOCK_SKEW_EXCEEDED` (`"CLOCK_001"`)
  * `REVOKED_ACCESS_ATTEMPT` (`"REVOKED_001"`)
  * `RAPID_SERVICE_HOP` (`"HOP_001"`)
* **`LogEvent`:** `(event_id: str, timestamp: float, received_at: float, actor: str, action: str, source_service: str, target_service: str, key_epoch: int, details: dict = {}, ordering_uncertain: bool = False)`
* **`Alert`:** `(alert_id: str, alert_type: AlertType, severity: Severity, actor: str, description: str, event_ids: List[str], violated_rule: str, services_involved: List[str], detected_at: float, ordering_uncertain: bool = False, auto_revoke_triggered: bool = False, violated_path: Optional[str] = None)`
* **`DetectionMetrics`:** `(true_positives=0, false_positives=0, false_negatives=0, true_negatives=0, time_to_alert_seconds=[], total_benign_events=0)` with methods:
  * `f1_score() -> float`: Harmonic mean of precision and recall.
  * `median_tta() -> float`: Median seconds across `time_to_alert_seconds`.
  * `fp_per_1000() -> float`: `(false_positives / total_benign_events) * 1000`.

### `WatchdogDetector` Constructor

```python
WatchdogDetector(
    allowed_paths: List[List[str]],
    clock_tolerance: float = 5.0,
    lateral_window: float = 60.0,
    lateral_max_hops: int = 3,
    critical_threshold: float = 0.85,
    revocation_callback: Optional[Callable] = None,
    admin_nodes: Set[str] = None,
    maintenance_windows: List[dict] = None,
)
```

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `allowed_paths` | `List[List[str]]` | Required | Permitted `[source, target]` service graph edges. |
| `clock_tolerance` | `float` | `5.0` | Clock-skew reorder buffer tolerance (`±seconds`). |
| `lateral_window` | `float` | `60.0` | Sliding window (seconds) for multi-hop lateral movement escalation. |
| `lateral_max_hops` | `int` | `3` | Hop count threshold within `lateral_window` to trigger `CRITICAL` `LAT_MOVE_001`. |
| `critical_threshold` | `float` | `0.85` | Severity score (`LOW=0.3, MEDIUM=0.5, HIGH=0.75, CRITICAL=1.0`) triggering `revocation_callback`. |
| `revocation_callback` | `Optional[Callable[[str], None]]` | `None` | Invoked with `alert.actor` when score meets `critical_threshold`. |
| `admin_nodes` | `Optional[Set[str]]` | `None` | Actor IDs authorized for privilege actions without alerting. |
| `maintenance_windows` | `Optional[List[dict]]` | `None` | List of `{"actor": str, "start": float, "end": float}` intervals suppressing routine maintenance escalation alerts. |

### `WatchdogDetector` Methods

| Method & Signature | Expected Inputs | Return Value / Output |
| :--- | :--- | :--- |
| `ingest_event(event: LogEvent)` | `LogEvent` | `List[Alert]` generated from events now settled past `clock_tolerance` |
| `flush()` | — | `List[Alert]` evaluated after draining all remaining buffered events in timestamp order |
| `add_revoked_node(node_id: str)` | `node_id: str` | `None`; future events from `node_id` immediately trigger `CRITICAL` `REVOKED_001` |
| `get_alerts(since: float = 0.0)` | Unix timestamp `since` | `List[Alert]` with `detected_at >= since` |
| `run_batch_evaluation(events: List[LogEvent], ground_truth: Dict[str, bool])` | Ordered/skewed events and `{event_id: is_attack}` map | `DetectionMetrics` (flushes buffer automatically and stores metrics on detector) |
| `get_metrics_report()` | — | `{"f1_score": float, "median_tta_seconds": float, "fp_per_1000_events": float, "total_alerts": int, "critical_alerts": int, "auto_revocations": int}` |
| `get_service_graph_summary()` | — | `{"allowed_paths": list, "actor_access_history": dict}` |

### Lower-Level Building Blocks (`src.sdk`)

* **`ClockSkewBuffer(tolerance_seconds=5.0, max_buffer_size=10000)`:** `ingest(event) -> List[LogEvent]`, `flush() -> List[LogEvent]`. Tags adjacent events within `tolerance_seconds` as `ordering_uncertain=True`.
* **`ServiceAccessGraph(allowed_paths)`:** `is_path_allowed(source, target) -> bool`, `record_access(actor, source, target, timestamp, event_id='')`, `check_lateral_movement(actor, window_seconds=60.0, max_hops=3, reference_time=None) -> Optional[dict]`, `check_unauthorized_path(actor, source, target) -> bool`, `get_summary() -> dict`.
* **`RuleEngine(admin_nodes=None, maintenance_windows=None)`:** `is_in_maintenance_window(actor, check_time) -> bool`, `check_privilege_escalation(event) -> Optional[Alert]`, `check_revoked_access(event, revoked_nodes) -> Optional[Alert]`, `check_replay_event(event) -> Optional[Alert]`.
