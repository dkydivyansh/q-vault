# Verification Suite & Benchmark Results

This document describes the automated verification suite under `tests/`, the isolation fixtures used during test execution, the catalog of all 26 test cases, the deterministic benchmark runner (`src/app/benchmark.py`), and observed performance measurements.

---

## 1. Running the Verification Suite

Run the full test suite in verbose mode from the repository root using Python 3.12 (`python3`):

```bash
python3 -m pytest tests/ -v --tb=short
```

Target an individual test suite or test function by file path or pytest node ID:

```bash
python3 -m pytest tests/test_crypto_protocol.py -v
python3 -m pytest tests/test_lifecycle_resilience.py::test_wal_crash_recovery_preserves_committed_state_and_revocations -v
```

### Verification Environment & Fixtures

All filesystem, SQLite, and HTTP state in `tests/` is created inside isolated temporary directories:

* **No shared fixtures or global state:** Every test case runs self-contained with freshly generated runtime identities (`ML-DSA-65`, `ML-KEM-768`, `X25519`) and ephemeral 256-bit `AES-256-GCM` master KEKs via `secrets.token_hex(32)`.
* **`tmp_path` isolation:** Persistence, WAL crash-recovery, ledger, and HTTP integration tests accept pytest's built-in `tmp_path: pathlib.Path` fixture to isolate SQLite WAL files, `.qvbak` encrypted backups, and JSONL ledger files per test invocation.
* **Subprocess WAL crash injection:** `test_wal_crash_recovery_preserves_committed_state_and_revocations` spawns an isolated child Python process (`subprocess.run([sys.executable, "-c", ...])`) that opens SQLite in `WAL` mode, executes `BEGIN IMMEDIATE` and inserts an uncommitted epoch (`99`), then terminates via `os._exit(1)` without calling `COMMIT`.
* **In-process HTTP verification:** `tests/test_app_integration.py` builds a fresh `SentinelRuntime` inside `tmp_path` and passes it to `create_web_console_app(runtime=runtime, config=cfg)` wrapped with `fastapi.testclient.TestClient`.

---

## 2. Automated Test Case Catalog (26 Tests)

### 2.1 Cryptographic Protocol Suite (`tests/test_crypto_protocol.py` — 9 Tests)

Helper fixture factory: `_create_gateway_pair(name_a: str = "NodeA", name_b: str = "NodeB")` instantiates two mutual `NodeGateway` instances (`NodeA`, `NodeB`) with registered `PeerInfo` records.

| Test Case | Arguments / Inputs | Expected Assertions & Outcome |
| :--- | :--- | :--- |
| `test_valid_aes_gcm_roundtrip` | None. Hybrid handshake (`epoch=1`), payload `b"Settlement transfer instruction #901"`, `msg_id="msg-1"`, `seq_num=1`. | Initiator and responder derive identical `SessionKeys`; `decrypt_chunk` recovers exact plaintext bytes. |
| `test_aad_recipient_tampering_raises` | None. Chunk encrypted for `sender="NodeA"`, `recipient="NodeB"`. | Calling `decrypt_chunk(..., "NodeA", "NodeC")` raises `cryptography.exceptions.InvalidTag`. |
| `test_mldsa_sign_verify_valid_and_tampered` | None. Payload `b"canonical-control-message"` signed under `CTX_HANDSHAKE`. | `verify_signature` returns `True` for intact data and `False` for `b"modified-message"`. |
| `test_domain_separation_rejects_cross_context_signature` | None. Payload `b"shared-payload"` signed under `CTX_HANDSHAKE`. | `verify_signature` with `CTX_REVOKE` returns `False` due to FIPS 204 context separation. |
| `test_anti_replay_window_blocks_duplicate_and_allows_reordering` | None. `AntiReplayWindow(window_size=64)`; sequence numbers `5`, `3`, `7`, `1`, then `5`, `3`. | Out-of-order sequences `5, 3, 7, 1` return `True`; subsequent duplicates `5` and `3` return `False`. |
| `test_forward_secrecy_session_keys_independent_of_long_term_signing_key` | None. Two handshakes (`hs_1`, `hs_2`) between the same identities; AES key forged from `SHA-256(mldsa_private)`. | `hs_1.session_keys.aes_key != hs_2.session_keys.aes_key` and distinct `session_id`; decrypting `hs_1` chunk with forged long-term key raises `InvalidTag`. |
| `test_chunk_reordering_and_incomplete_transfer_timeout` | None. Payload `os.urandom(65536 + 500)` (`chunks_sent == 2`); chunk `1` delivered before chunk `0`; partial 2-chunk transfer cleaned via `reassembly_timeout_seconds=-1.0`. | Chunk `1` returns `None`, chunk `0` reassembles exact plaintext; `cleanup_stale_sessions` returns `>= 1` expired partial buffer. |
| `test_resumption_ticket_peer_binding` | None. Encrypted ticket generated for `NodeA` on `NodeB` with random 32-byte `master_kek`. | `resume_session` returns `None` for spoofed `"NodeC"`, returns a new rotated `session_id != sid_b` once for `"NodeA"`, and returns `None` on single-use ticket replay. |
| `test_per_session_replay_isolation_and_aad_seq_desync_blocked` | None. Concurrent sessions `NodeA -> NodeB` and `NodeC -> NodeB`; forged `seq_num=999999` injected on session 1. | Tampered `seq_num=999999` fails AAD check (`None`) without advancing session 1 replay window; legitimate `seq_num=0` succeeds once (`b"from-A"`), replays fail (`None`), and `NodeC` session independently accepts `seq_num=0` (`b"from-C"`). |

---

### 2.2 Lifecycle, Crash Recovery & Resilience Suite (`tests/test_lifecycle_resilience.py` — 5 Tests)

Helper factory: `_register_gateway(auth: KeyAuthority, node_id: str) -> tuple[NodeGateway, PeerInfo]`.

| Test Case | Arguments / Inputs | Expected Assertions & Outcome |
| :--- | :--- | :--- |
| `test_epoch_rotation_grace_window_and_hard_cutoff` | `tmp_path`. `KeyAuthority(..., grace_period_seconds=30.0)`; rotations to epoch `1` and epoch `2`. | Epoch `0` remains valid within `+10.0s` of rotation `1` and invalid after `rot1.cutoff + 0.1s`; rotating to epoch `2` keeps epoch `1` valid inside its grace window while immediately invalidating epoch `0`. |
| `test_cross_node_revocation_propagation_and_re_enrollment` | `tmp_path`. 3 registered nodes (`NodeA`, `NodeB`, `NodeC`); revokes `NodeA` (`reason="compromised-device"`); re-enrolls `NodeA_v2` with `previous_node_id="NodeA"`. | `get_propagation_stats` reports `total_acked == 3` and `max_propagation_ms >= 0.0`; handshake toward `NodeA` raises `PermissionError`; `NodeB <-> NodeC` transfers remain unaffected; `NodeA_v2` is active while `NodeA` remains permanently revoked. |
| `test_backup_and_corrupt_backup_rejection` | `tmp_path`. `.qvbak` exported via `backup_keys()`, then mutated by 1 byte (`raw[60] ^= 0x01`). | Original backup restores (`True`); 1-byte corrupted backup raises `ValueError` upon `restore_from_backup`. |
| `test_wal_crash_recovery_preserves_committed_state_and_revocations` | `tmp_path`. Commits `NodeA` (revoked `"pre-crash-revocation"`) and `NodeB` at epoch `1`; child process injects uncommitted epoch `99` and calls `os._exit(1)`. | Child exits with code `1`; reopened `KeyAuthority` recovers `current_epoch == 1`, `is_revoked("NodeA") is True`, and `is_revoked("NodeB") is False`. |
| `test_restart_persists_revocations_across_nodes_and_ledger_checkpoints` | `tmp_path`. `SentinelRuntime` (`checkpoint_interval=3`), transfers `WebPortal -> Auth`, revokes `FileGateway` (`"compromise-before-restart"`), closes runtime, instantiates fresh `SentinelRuntime(cfg)`. | Post-restart `FileGateway` remains revoked across authority and gateways; transfer `WebPortal -> FileGateway` raises `PermissionError`; `SERVICE_CALL` by `FileGateway` emits `REVOKED_001`; `ledger.verify_chain()` passes with `bad_checkpoints == []`. |

---

### 2.3 Ledger & Deterministic Detection Suite (`tests/test_detector_ledger.py` — 7 Tests)

Test topology (`ALLOWED_PATHS`): 8 authorized directed service edges (`WebPortal->Auth`, `WebPortal->FileGateway`, `Auth->Billing`, `Auth->UserDB`, `FileGateway->VaultDB`, `Billing->PayrollDB`, `Admin->Auth`, `Admin->UserDB`).

| Test Case | Arguments / Inputs | Expected Assertions & Outcome |
| :--- | :--- | :--- |
| `test_log_injection_escaped_as_single_json_line` | `tmp_path`. Actor `'alice\n{"actor":"admin","action":"grant"}'`, action `"LOGIN"`. | `audit.jsonl` contains exactly `1` serialized line; `json.loads(lines[0])["actor"]` equals the raw injected string. |
| `test_log_chain_verification_and_tamper_detection` | `tmp_path`. `6` logged entries (`checkpoint_interval=3`), followed by modifying entry `1` `actor` field on disk to `"MaliciousAdmin"`. | Initial `verify_chain()` returns `ok=True`, `total_entries=6`; after file mutation, `verify_chain()` returns `ok=False` with `1 in tampered_entries`. |
| `test_clock_skew_reorder_and_ordering_uncertain_flag` | None. Events arriving out of order (`base + 1.5s`, then `base + 0.2s`) within `clock_tolerance=5.0`, followed by `flush()`. | Unauthorized edge `VaultDB -> PayrollDB` (`"e2"`) triggers alert with `ordering_uncertain is True` and `event_ids == ["e2"]`. |
| `test_context_aware_privilege_escalation_rules` | None. `admin_nodes={"Admin"}`, active `MaintUser` window (`[now - 60.0, now + 60.0]`), plus `"grant_admin"` event from `"RegularUser"`. | Authorized admin and maintenance actions generate `0` false alerts; `"RegularUser"` raises `AlertType.PRIVILEGE_ESCALATION`. |
| `test_lateral_movement_and_auto_revocation_callback` | None. 3-hop chain `WebPortal -> FileGateway -> VaultDB -> PayrollDB` (`lateral_window=60.0`, `lateral_max_hops=3`), plus follow-up `WebPortal -> Auth` event. | `CRITICAL` `AlertType.LATERAL_MOVEMENT` (`violated_rule="LAT_MOVE_001"`) names actor `"CompromisedNode"`, all `3` event IDs, all `4` services, and `VaultDB->PayrollDB`; callback adds `"CompromisedNode"` to revoked set; follow-up event emits `AlertType.REVOKED_ACCESS_ATTEMPT`. |
| `test_benchmark_runner_produces_real_metrics` | None. Calls `run_benchmark(handshake_iterations=5, chunk_iterations=10, benign_events=100, attack_events=12)`. | Verifies `grace_period_seconds == 30.0`, `handshake_ms["median"] > 0.0`, `nodes_acked == 8`, `f1_score > 0.9`, and `fp_per_1000_benign == 0.0`. |
| `test_batch_evaluation_metrics_f1_tta_and_fp_per_1000` | None. `2` benign events (`b1`, `b2`) and `2` attack events (`a1` unauthorized edge, `a2` `"grant_admin"`) with `clock_tolerance=5.0`. | `metrics.f1_score() > 0.99`, `metrics.fp_per_1000() == 0.0`, `metrics.median_tta() >= 0.0`, and `get_metrics_report()["f1_score"] > 0.99`. |

---

### 2.4 HTTP Application & Web Console Suite (`tests/test_app_integration.py` — 5 Tests)

Helper factory: `_make_test_client(tmp_path)` creates isolated `SentinelRuntime` and FastAPI `TestClient`.

| Test Case | Arguments / Inputs | Expected Assertions & Outcome |
| :--- | :--- | :--- |
| `test_web_console_and_status_endpoints` | `tmp_path`. `GET /` and `GET /api/v1/status`. | HTML console returns `200` containing `"Q-Vault Sentinel Control Plane"`; status returns `200` with `8` registered services and `current_epoch == 0`. |
| `test_http_service_node_handshake_transfer_and_replay_rejection` | `tmp_path`. HTTP `POST /nodes/Auth/pqc/handshake`, encrypted payload delivery to `POST /nodes/Auth/pqc/receive`, then identical duplicate delivery. | Handshake returns matching `session_id_hex`; initial chunk returns `status == "delivered"` with exact recovered hex plaintext; duplicate replay returns `status == "pending_or_rejected"`. |
| `test_http_lateral_movement_triggers_auto_revocation_and_ledger_verifies` | `tmp_path`. `POST /api/v1/scenarios/lateral-movement`, post-revocation `FileGateway -> VaultDB` transfer, unaffected `WebPortal -> Auth` transfer, and `GET /api/v1/ledger/verify`. | Lateral movement revokes `"FileGateway"`; `FileGateway -> VaultDB` returns HTTP `403`; `WebPortal -> Auth` returns `200` (`verified_match: true`); ledger verification returns `ok: true`. |
| `test_http_service_node_resumption_hijack_blocked` | `tmp_path`. Ticket issued via `POST /nodes/Auth/pqc/ticket`; claimed as `"PayrollDB"`, then `"WebPortal"`, then replayed as `"WebPortal"`. | Cross-peer hijack returns HTTP `403`; valid claim returns HTTP `200` with rotated `session_id_hex`; single-use ticket replay returns HTTP `403`. |
| `test_security_probes_re_enroll_and_epoch_check` | `tmp_path`. Exercises `/api/v1/probes/{aad-tamper,replay,resumption-hijack,backup-tamper,clock-skew}`, `/api/v1/authority/{rotate,epoch-check,backup,backups,revoke,re-enroll}`. | Confirms `InvalidTag` AAD rejection, replay block, resumption hijack/replay rejection, `.qvbak` corruption rejection, `ordering_uncertain` clock-skew flush, grace/post-cutoff validity, backup listing, and re-enrollment of `FileGateway_v2`. |

---

## 3. Deterministic Benchmark Runner (`src/app/benchmark.py`)

### Function API

```python
from src.app.benchmark import run_benchmark

results = run_benchmark(
    handshake_iterations: int = 20,
    chunk_iterations: int = 50,
    benign_events: int = 1000,
    attack_events: int = 50,
) -> dict
```

**Parameters:**

* `handshake_iterations` (`int`, default `20`): Number of end-to-end `WebPortal <-> Auth` hybrid `X25519 + ML-KEM-768 + ML-DSA-65` handshakes timed.
* `chunk_iterations` (`int`, default `50`): Number of 64 KiB (`65,536`-byte) `AES-256-GCM` encrypt-and-decrypt roundtrips timed.
* `benign_events` (`int`, default `1000`): Number of synthetic benign telemetry events generated across the 6 non-admin edges plus legitimate `Admin` and `MaintSvc` maintenance-window actions.
* `attack_events` (`int`, default `50`): Number of malicious events distributed evenly modulo 3 across unauthorized edges (`VaultDB->PayrollDB`, `UserDB->PayrollDB`, `PayrollDB->VaultDB`, `WebPortal->PayrollDB`), unauthorized `"grant_admin"` privilege escalations, and `"REPLAY_DETECTED"` telemetry events.

**CLI Execution:**

```bash
python3 -m src.app.console benchmark
```

**Returned JSON Structure:**

Top-level keys returned by `run_benchmark()` and printed by the CLI command:
* `grace_period_seconds`: Configured rotation grace interval (`30.0`).
* `handshake_ms`: `{"min": float, "median": float, "max": float}` in milliseconds.
* `aes_gcm_64kb_roundtrip`: `{"median_ms": float, "throughput_mb_s": float}`.
* `revocation_propagation_ms`: `{"nodes_acked": int, "min": float, "max": float}`.
* `ledger_200_entries`: `{"write_ms": float, "verify_ms": float}` (`checkpoint_interval=50`).
* `detection_benchmark`: `{"total_events", "benign_events", "attack_events", "true_positives", "false_positives", "false_negatives", "true_negatives", "f1_score", "median_tta_seconds", "batch_eval_ms", "fp_per_1000_benign", "ordering_uncertain_alerts", "auto_revocations"}`.

---

## 4. Observed Verification & Benchmark Results

All metrics below were recorded verbatim from local execution of the verification suite (`python3 -m pytest tests/ -v --tb=short`) and `python3 -m src.app.console benchmark` in this workspace:

### Suite Status

* **Automated Pytest Suite:** `26/26` tests passing across `tests/test_crypto_protocol.py` (9), `tests/test_lifecycle_resilience.py` (5), `tests/test_detector_ledger.py` (7), and `tests/test_app_integration.py` (5).

### Cryptographic, Lifecycle & Ledger Benchmarks

| Metric | Observed Value | Workload Scope |
| :--- | :--- | :--- |
| **Hybrid PQC Handshake Latency (`X25519 + ML-KEM-768 + ML-DSA-65`)** | `2.128 ms` median (`1.341 ms` min / `4.497 ms` max) | 20 consecutive initiator + responder handshakes |
| **64 KiB `AES-256-GCM` Chunk Roundtrip** | `0.148 ms` median (`346.17 MB/s`) | 50 encrypt + AAD verify + decrypt cycles |
| **Key Rotation Grace Period** | `30.0 s` | Authority rotation policy window |
| **Cross-Node Emergency Revocation Propagation** | `2.759 ms` min / `15.506 ms` max (`8/8` nodes acked) | Signed revocation broadcast to all 8 service nodes |
| **Audit Ledger Write Speed** | `413.15 ms` (`~2.07 ms/entry`) | 200 canonical JSONL + SHA-256 chain appends (4 `ML-DSA-65` checkpoints) |
| **Audit Ledger Chain Verification** | `19.56 ms` | Full re-hash and `ML-DSA-65` checkpoint verification across 200 records |

### Deterministic Detection Engine Benchmarks (`1,050` Mixed Events)

| Metric | Observed Value |
| :--- | :--- |
| **Workload Mix** | `1,000` benign events + `50` attack events (`1,050` total) |
| **Confusion Matrix** | `TP = 50`, `FP = 0`, `FN = 0`, `TN = 1,000` |
| **F1 Score** | `1.0` |
| **False Positives per 1,000 Benign Events** | `0.0` |
| **Median Time-to-Alert (TTA)** | `4.6002 s` (includes `5.0 s` clock-skew buffer residency before flush) |
| **Batch Evaluation Runtime** | `42.3 ms` |
| **Clock-Skew Uncertain Alerts Flagged** | `61` (`ordering_uncertain=True` under simulated skew) |
| **Automated Revocations Triggered** | `9` distinct compromised identities contained |
