# Operations, CLI & HTTP API Reference

This guide covers environment setup, configuration management (`config/`), the closed-loop application runtime (`src/app/`), the Operator CLI, and the FastAPI Control Plane and Service Node HTTP interfaces.

---

## 1. Environment Setup & Installation

### Requirements

* **Python:** 3.12+ (recommended; tested with `cryptography 50.0.1`)
* **Dependencies (`requirements.txt`):**
  * `cryptography>=50.0.1` (`ML-DSA-65`, `ML-KEM-768`, `X25519`, `AES-256-GCM`, `HKDF-SHA256`)
  * `fastapi>=0.142.0`, `uvicorn>=0.54.0`, `httpx>=0.28`, `aiohttp>=3.14`
  * `pyyaml>=6.0`, `click>=8.0`, `rich>=13.0`
  * `pytest>=8.0`, `pytest-asyncio>=0.24`

### Installation

```bash
python3 -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Optionally copy the environment template and supply a persistent 256-bit (64-hex-character) master key-encryption key:

```bash
cp config/.env.example .env
# Generate a 256-bit KEK for .env:
python3 -c "import secrets; print('QVAULT_MASTER_KEK=' + secrets.token_hex(32))"
```

> **Runtime Secret Generation:** If `QVAULT_MASTER_KEK` is unset or left as the placeholder in `config/.env.example`, `load_config()` automatically generates a fresh ephemeral key at runtime via `secrets.token_hex(32)`. Configure a persistent `QVAULT_MASTER_KEK` when key backups (`.qvbak`) or sealed keys must be decrypted after process restarts.

---

## 2. Configuration & Policy (`config/` & `src/app/config.py`)

### Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `QVAULT_POLICY_PATH` | `config/policy.yaml` | Override path to the YAML policy file loaded by `load_config()`. |
| `QVAULT_MASTER_KEK` | Ephemeral `secrets.token_hex(32)` | 64-character hex string representing the 256-bit AES-GCM master key-encryption key. |
| `QVAULT_AUTHORITY_HOST` | `127.0.0.1` | Bind host recorded in `SentinelConfig.host`. |
| `QVAULT_AUTHORITY_PORT` | `8700` | Bind port recorded in `SentinelConfig.port`. |
| `QVAULT_DB_PATH` | `./data/authority.db` | SQLite WAL state database path for `KeyAuthority`. |
| `QVAULT_LEDGER_PATH` | `./data/audit.jsonl` | Canonical JSONL audit chain path for `AuditLedger`. |
| `QVAULT_BACKUP_PATH` | `./data/backups/` | Output directory used by `SentinelRuntime.backup_authority()`. |

### Policy File (`config/policy.yaml`)

Default configuration values defined in `config/policy.yaml`:

```yaml
rotation:
  grace_period_seconds: 30
  interval_seconds: 300

clock_skew:
  tolerance_seconds: 5

anti_replay:
  window_size: 1024
  sequence_bits: 64

session_resumption:
  ticket_ttl_seconds: 3600

service_graph:
  allowed_paths:
    - [WebPortal, Auth]
    - [WebPortal, FileGateway]
    - [Auth, Billing]
    - [Auth, UserDB]
    - [FileGateway, VaultDB]
    - [Billing, PayrollDB]
    - [Admin, Auth]
    - [Admin, UserDB]
    - [Admin, VaultDB]
    - [Admin, Billing]
    - [Admin, PayrollDB]
  lateral_movement_window_seconds: 60
  lateral_movement_max_hops: 3

detection:
  critical_severity_threshold: 0.85
  rules:
    - id: PRIV_ESC_001
      name: Unauthorized Privilege Escalation
    - id: LAT_MOVE_001
      name: Lateral Movement via Service Graph
    - id: REPLAY_001
      name: Replay Attack Detected
    - id: CLOCK_001
      name: Clock Skew Exceeded

ledger:
  checkpoint_interval: 100
  algorithm: ML-DSA-65

authority:
  key_algorithm: ML-DSA-65
  kem_algorithm: ML-KEM-768
  hybrid_kem: true
```

### Configuration Loader API (`src/app/config.py`)

```python
from src.app.config import SentinelConfig, load_policy, load_config
```

* **`load_policy(policy_path: str = "config/policy.yaml") -> Dict[str, Any]`** — Parses the YAML policy file if present; returns `{}` if missing or non-mapping.
* **`load_config(policy_path: str = "config/policy.yaml", db_path: str | None = None, ledger_path: str | None = None, backup_dir: str | None = None, master_kek_hex: str | None = None) -> SentinelConfig`** — Resolves `SentinelConfig` from explicit keyword arguments, environment variables, and `policy.yaml` defaults.

**`SentinelConfig` Fields & Defaults:**

| Field | Type | Default |
| :--- | :--- | :--- |
| `db_path` | `str` | From `load_config` (`./data/authority.db`) |
| `ledger_path` | `str` | From `load_config` (`./data/audit.jsonl`) |
| `backup_dir` | `str` | From `load_config` (`./data/backups/`) |
| `master_kek_hex` | `str` | From `load_config` (64 hex chars) |
| `grace_period_seconds` | `float` | `30.0` |
| `clock_tolerance_seconds` | `float` | `5.0` |
| `lateral_window_seconds` | `float` | `60.0` |
| `lateral_max_hops` | `int` | `3` |
| `critical_severity_threshold` | `float` | `0.85` |
| `checkpoint_interval` | `int` | `100` |
| `allowed_paths` | `List[List[str]]` | `DEFAULT_ALLOWED_PATHS` (11 service edges) |
| `host` | `str` | `"127.0.0.1"` |
| `port` | `int` | `8700` |

---

## 3. Application Runtime (`src/app/runtime.py`)

`SentinelRuntime(config: SentinelConfig)` connects the four SDK subsystems into an automated closed loop:

* **Default Enterprise Topology (`DEFAULT_TOPOLOGY_SERVICES`):** `("WebPortal", "Auth", "FileGateway", "Billing", "UserDB", "VaultDB", "PayrollDB", "Admin")`.
* **Persistent Ledger Identity:** Obtains or generates a dedicated `ML-DSA-65` signing identity via `authority.get_or_create_ledger_signing_key()`, isolated from the authority root signing key per NIST FIPS 204 Clause 8.
* **Event-Driven Wiring:**
  * Registers `_on_ledger_entry` on `AuditLedger`, automatically forwarding `MESSAGE_SEND`, `HANDSHAKE_INIT`, and `REPLAY_DETECTED` telemetry into `WatchdogDetector`.
  * Registers `_on_watchdog_revocation` on `WatchdogDetector`, automatically calling `authority.revoke_node(actor, reason="watchdog-automated-containment")`.
  * Registers `_broadcast_revocation` on `KeyAuthority`, delivering signed `RevocationNotice` objects to all in-process `NodeGateway` instances, updating `detector.add_revoked_node()`, and appending `REVOCATION_BROADCAST` to `AuditLedger`.

### Primary `SentinelRuntime` Methods

| Method | Signature | Returns |
| :--- | :--- | :--- |
| `register_service_node` | `(node_id: str) -> NodeGateway` | Idempotently provisions `ML-DSA-65`/`ML-KEM-768`/`X25519` keys, registers with `KeyAuthority`, meshes peer keys across all active gateways, and logs `NODE_REGISTERED`. |
| `provision_default_topology` | `() -> List[str]` | Provisions all 8 `DEFAULT_TOPOLOGY_SERVICES` and returns their IDs. |
| `send_encrypted_transfer` | `(source_node: str, target_node: str, payload: bytes) -> dict` | Runs hybrid handshake (`initiate_handshake`/`complete_handshake`) + chunked AES-GCM transfer; raises `ValueError`, `PermissionError`, or `RuntimeError` on unregistered or revoked peers. Returns `{"msg_id", "session_id", "epoch", "chunks_sent", "delivery_ms", "verified_match", "bytes_delivered"}`. |
| `rotate_epoch` | `() -> dict` | Calls `authority.rotate_keys()`, logs `KEY_ROTATE`, returns `{"epoch", "valid_from", "grace_until", "cutoff"}`. |
| `revoke_node` | `(node_id: str, reason: str = "operator-triggered") -> dict` | Revokes `node_id` and returns `{"node_id", "revocation_epoch", "revoked_at", "reason", "propagation"}`. |
| `ingest_service_event` | `(actor: str, action: str, source_service: str, target_service: str, timestamp: float \| None = None, flush_immediately: bool = False, details: dict \| None = None) -> List[dict]` | Appends canonical event to `AuditLedger`, ingests `LogEvent` into `WatchdogDetector`, optionally calls `flush()`, and returns serialized alert dicts. |
| `backup_authority` | `(filename: str \| None = None) -> dict` | Writes signed/encrypted `.qvbak` under `config.backup_dir`, logs `KEY_BACKUP`, returns `{"path", "checksum", "size"}`. |
| `list_backups` | `() -> List[dict]` | Lists up to 15 `.qvbak` archives in `config.backup_dir` ordered newest first (`name`, `path`, `size`, `modified_at`). |
| `re_enroll_service_node` | `(previous_node_id: str, new_node_id: str) -> dict` | Provisions fresh PQC keys for `new_node_id` while enforcing permanent revocation on `previous_node_id`. |
| `get_epoch_status` | `(query_epoch: int \| None = None, offset_seconds: float = 0.0) -> dict` | Evaluates `is_epoch_valid()` for a target epoch at `now + offset_seconds` alongside grace-window telemetry. |
| `probe_replay_rejection` / `probe_aad_tampering` / `probe_resumption_hijack` / `probe_backup_tamper` / `probe_clock_skew` | `(defaults)` -> `dict` | Executes live cryptographic and detector verification probes directly against SDK primitives and logs audited outcomes. |
| `get_snapshot` | `() -> dict` | Returns control-plane telemetry (`current_epoch`, `revocation_epoch`, `checkpoint_interval`, `epoch_status`, `nodes`, `revocations`, `recent_backups`, `alerts`, `metrics`, `service_graph`, `ledger_summary`, `recent_entries`). |
| `close` | `() -> None` | Closes underlying `KeyAuthority` SQLite WAL connection. |

---

## 4. Operator CLI (`python3 -m src.app.console`)

Invoke `--help` on the root group or any subcommand for inline usage:

```bash
python3 -m src.app.console --help
```

### `serve` — Start Control Plane, Service Nodes & Web Console

```bash
python3 -m src.app.console serve [--host TEXT] [--port INTEGER] [--db-path TEXT] [--ledger-path TEXT]
```

* `--host TEXT` (`default: 127.0.0.1`) — HTTP bind address.
* `--port INTEGER` (`default: 8700`) — HTTP listen port.
* `--db-path TEXT` — Optional override for SQLite WAL path (`load_config` default applies if omitted).
* `--ledger-path TEXT` — Optional override for JSONL audit ledger path.
* **Behavior:** Loads `SentinelConfig`, builds the FastAPI app via `create_web_console_app()`, provisions the 8 default services if not yet present, prints URLs (`http://<host>:<port>/` and `/api/v1/status`), and runs `uvicorn.run(...)`.

### `demo` — Execute End-to-End Operational Walkthrough

```bash
python3 -m src.app.console demo
```

* **Options:** `--help` only. Runs cleanly in an isolated temporary directory (`tempfile.TemporaryDirectory`) with `grace_period_seconds=1.0` and `checkpoint_interval=4`.
* **Walkthrough Steps:**
  1. **Service Node Registration:** Provisions all 8 services in SQLite WAL and prints the registry table.
  2. **Hybrid Handshake & Recipient-Bound Transfer:** Executes `WebPortal -> Auth` encrypted transfer, then deliberately tests cross-recipient AAD substitution (`WebPortal -> PayrollDB`) confirming `InvalidTag` rejection.
  3. **Key Rotation Grace Window & Cutoff:** Rotates epoch and evaluates `is_epoch_valid` inside the grace window (`True`) vs. post-cutoff (`False`).
  4. **Lateral Movement Detection & Automated Revocation:** Ingests unauthorized multi-hop path `WebPortal -> FileGateway -> VaultDB -> PayrollDB` for `FileGateway`, triggering `WatchdogDetector` containment and confirming `authority.is_revoked("FileGateway") == True`.
  5. **Tamper-Evident Audit Chain Verification:** Runs `ledger.verify_chain()` and reports chain validity.

### `benchmark` — Run Performance & Detection Benchmark

```bash
python3 -m src.app.console benchmark
```

* **Options:** `--help` only. Invokes `src.app.benchmark.run_benchmark()` and prints formatted JSON metrics to stdout. See [Verification Suite & Benchmark Results](testing.md) for output schema and observed values.

### `status` — Inspect Authority State & Ledger Head

```bash
python3 -m src.app.console status [--db-path TEXT] [--ledger-path TEXT]
```

* `--db-path TEXT` (`default: ./data/authority.db`) — Authority SQLite database.
* `--ledger-path TEXT` (`default: ./data/audit.jsonl`) — Audit ledger file.
* **Expected Output:** Rich table listing up to 20 registered nodes (`Node ID`, `Epoch`, `ACTIVE` / `REVOKED` status, UTC registration timestamp) plus summary panel (`Total Nodes`, `Active Nodes`, `Revoked Nodes`, `Current Epoch`, and 16-char `Chain Head` prefix). Exits `1` on database error.

### `watch` — Live Terminal Telemetry Monitor

```bash
python3 -m src.app.console watch [--db-path TEXT] [--ledger-path TEXT]
```

* `--db-path TEXT` (`default: ./data/authority.db`)
* `--ledger-path TEXT` (`default: ./data/audit.jsonl`)
* **Behavior:** Full-screen Rich `Live` layout refreshing every 2 seconds showing active/revoked node status (up to 10 rows), the 5 most recent security alert entries (`REVOKE`, `ALERT`, `REPLAY`, `TAMPER`, `LATERAL`, `PRIV_ESC`, `CRITICAL`) scanned from the last 50 ledger lines, current epoch, revocation count, and chain head hash. Press `Ctrl+C` to exit cleanly.

### `verify-log` — Offline Audit Chain & Checkpoint Verifier

```bash
python3 -m src.app.console verify-log [--ledger-path TEXT] [--signing-key-path TEXT]
```

* `--ledger-path TEXT` (`default: ./data/audit.jsonl`)
* `--signing-key-path TEXT` (`default: None`) — Optional path to raw `ML-DSA-65` public key bytes (`load_mldsa_public_key`) for strict checkpoint signature verification. Without `--signing-key-path`, hash-chain tamper checks run against every entry while checkpoint signatures require the authority/ledger verify key.
* **Exit Behavior:** Prints green verification confirmation with verified entry count (`exit 0`), or prints the tampered entry indices / failure message in red and exits with status `1`. Exits `1` if `--ledger-path` does not exist.

### `revoke` — Execute Emergency Key Revocation

```bash
python3 -m src.app.console revoke [--db-path TEXT] [--reason TEXT] NODE_ID
```

* `NODE_ID` (required positional argument) — Identifier of the node to revoke.
* `--db-path TEXT` (`default: ./data/authority.db`)
* `--reason TEXT` (`default: operator-triggered`)
* **Expected Output:** Revokes `NODE_ID` in `KeyAuthority`, prints the assigned `revocation_epoch`, and displays the `Propagation Stats` table (`Revocation Epoch`, `Total Acked`, `Max Propagation (ms)`, `Min Propagation (ms)`). Exits `1` if revocation raises an error (e.g., unknown `NODE_ID`).

---

## 5. Control Plane HTTP REST API (`/api/v1/*`)

Defined in `src/app/authority_server.py` and mounted by `create_web_console_app()`.

### Control Plane & Key Lifecycle Endpoints

| Method & Path | Request JSON Schema | Success (`200`) Response / Error Codes |
| :--- | :--- | :--- |
| `GET /api/v1/health` | — | `{"status": "ok", "epoch": int, "revocation_epoch": int}` |
| `GET /api/v1/status` | — | Full `SentinelRuntime.get_snapshot()` JSON object. |
| `POST /api/v1/authority/nodes/register` | `{"node_id": str, "signing_public_hex": str, "kem_public_hex": str, "x25519_public_hex": str}` | `200`: `{"node_id", "key_epoch", "registered_at"}` · `400`: Duplicate node ID or invalid hex/key length. |
| `POST /api/v1/authority/rotate` | — | `200`: `{"epoch", "valid_from", "grace_until", "cutoff"}` |
| `POST /api/v1/authority/revoke` | `{"node_id": str, "reason": str = "operator-triggered"}` | `200`: `{"node_id", "revocation_epoch", "revoked_at", "reason", "propagation"}` · `404`: Node ID not found (`ValueError`). |
| `POST /api/v1/authority/backup` | — | `200`: `{"path": str, "checksum": str, "size": int}` |
| `GET /api/v1/authority/backups` | — | `200`: `{"backups": [{"name", "path", "size", "modified_at"}]}` |
| `POST /api/v1/authority/restore` | `{"backup_path": str}` | `200`: `{"restored": bool}` · `400`: Signature invalid, corrupted ciphertext, wrong KEK, or file I/O failure. |
| `POST /api/v1/authority/re-enroll` | `{"previous_node_id": str, "new_node_id": str}` | `200`: `{"node_id", "previous_node_id", "key_epoch", "registered_at"}` · `400`: Duplicate target ID or previous node not revoked. |
| `GET /api/v1/authority/epoch-check` | Query: `epoch: int \| null = null`, `offset_seconds: float = 0.0` | `200`: `{"query_epoch", "offset_seconds", "is_valid", "current_epoch", "prior_epoch", "prior_epoch_valid", "grace_period_seconds"}` |
| `POST /api/v1/gateway/transfer` | `{"source_node": str, "target_node": str, "payload_text": str}` | `200`: `{"msg_id", "session_id", "epoch", "chunks_sent", "delivery_ms", "verified_match", "bytes_delivered"}` · `403`: Unknown node, revoked node, or encryption/verification rejection. |

### Audit Ledger, Watchdog Detector & Verification Probe Endpoints

| Method & Path | Query / Request Schema | Success (`200`) Response |
| :--- | :--- | :--- |
| `GET /api/v1/ledger/verify` | — | `{"ok": bool, "total_entries": int, "tampered_entries": List[int], "bad_checkpoints": List[int], "message": str}` |
| `GET /api/v1/ledger/entries` | Query: `since_id: int = 0`, `limit: int = 50` | `{"entries": [{"entry_id", "timestamp", "actor", "action", "target", "prev_hash", "entry_hash", "is_checkpoint", "checkpoint_signature"}]}` |
| `POST /api/v1/detector/events` | `{"actor": str, "action": str, "source_service": str, "target_service": str, "timestamp": float \| null = null, "flush_immediately": bool = true}` | `{"alerts": List[dict], "metrics": dict}` |
| `POST /api/v1/detector/flush` | — | Flushes buffered clock-skew events: `{"alerts": List[dict], "metrics": dict}` |
| `GET /api/v1/detector/alerts` | — | `{"alerts": List[dict]}` |
| `GET /api/v1/detector/metrics` | — | `WatchdogDetector.get_metrics_report()` JSON object. |
| `GET /api/v1/detector/graph` | — | `WatchdogDetector.get_service_graph_summary()` JSON (`{"allowed_paths": List[List[str]], "actor_access_history": Dict[str, List[dict]]}`). |
| `POST /api/v1/scenarios/lateral-movement` | — | Injects `WebPortal -> FileGateway -> VaultDB -> PayrollDB -> Admin` sequence under `FileGateway`; returns `{"actor": "FileGateway", "is_revoked": bool, "alerts": List[dict]}`. |
| `POST /api/v1/probes/replay` | `{"source_node": str = "WebPortal", "target_node": str = "Auth"}` | Verifies sliding-window duplicate sequence rejection and `REPLAY_001` alert emission (`403` if peer revoked). |
| `POST /api/v1/probes/aad-tamper` | `{"source_node": str = "WebPortal", "target_node": str = "Auth", "spoofed_recipient": str = "PayrollDB"}` | Verifies `AES-256-GCM` raises `InvalidTag` on recipient substitution. |
| `POST /api/v1/probes/resumption-hijack` | `{"authorized_peer": str = "WebPortal", "host_node": str = "Auth", "impersonator_peer": str = "PayrollDB"}` | Verifies peer-bound hijack rejection, valid session rotation, and single-use ticket replay block (`403` if peer revoked). |
| `POST /api/v1/probes/backup-tamper` | — | Exports temporary `.qvbak`, confirms clean restore, flips 1 byte, and verifies `ValueError` rejection. |
| `POST /api/v1/probes/clock-skew` | — | Feeds skewed events inside tolerance window, confirms buffering before flush, and verifies `ordering_uncertain=true`. |

---

## 6. Protected Service Node Endpoints (`/nodes/{node_id}/*`)

Each service gateway (`WebPortal`, `Auth`, `FileGateway`, `Billing`, `UserDB`, `VaultDB`, `PayrollDB`, `Admin`) mounts an independent FastAPI sub-application created by `create_service_node_app()` (`src/app/service_node.py`):

| Method & Path | Request Schema | Response & Status Behavior |
| :--- | :--- | :--- |
| `GET /nodes/{node_id}/health` | — | `200`: `{"status": "ok", "node_id": str, "signing_public_hex", "kem_public_hex", "x25519_public_hex"}` (pubkey fields included when `peer_info` is supplied). |
| `POST /nodes/{node_id}/pqc/handshake` | `{"peer_node_id": str, "kem_ciphertext_hex": str, "ephemeral_x25519_pub_hex": str, "peer_signature_hex": str, "epoch": int}` | `200`: `{"session_id_hex": str}` · `403`: Unknown peer, revoked peer, invalid epoch, or bad `ML-DSA-65` transcript signature. |
| `POST /nodes/{node_id}/pqc/receive` | `{"session_id_hex": str, "nonce_hex": str, "ciphertext_hex": str, "aad_json": str, "seq_num": int}` | `200`: `{"status": "delivered", "reassembled_hex": str, "bytes": int}` when all chunks arrive and verify, or `{"status": "pending_or_rejected", "reassembled_hex": null}` if awaiting chunks, replayed, or rejected. |
| `POST /nodes/{node_id}/pqc/ticket` | `{"session_id_hex": str}` | `200`: `{"ticket_hex": str}` · `400`: Unknown session ID (`ValueError`). |
| `POST /nodes/{node_id}/pqc/resume` | `{"ticket_hex": str, "claiming_peer_id": str}` | `200`: `{"session_id_hex": str}` · `403`: Resumption rejected (peer mismatch, revoked peer, expired, invalid AEAD tag, or ticket replay). |
| `POST /nodes/{node_id}/pqc/revocation` | `{"node_id": str, "revocation_epoch": int, "revoked_at": float, "reason": str, "signature_hex": str, "authority_public_key_hex": str}` | `200`: `{"enforced": true, "node_id": str}` · `400`: Invalid `ML-DSA-65` authority signature. |

---

## 7. Web Console (`GET /`)

Serving `src/app/static/index.html` at `http://<host>:<port>/`, the console renders a true-black (`#000000`) dark-theme workspace organized across four accessible tabs:

* **Global Command Bar & Operational Telemetry Strip:** Sticky header with authority health indicator, `Refresh`, `Rotate epoch`, and `Verify chain` actions paired with live counters (`Active key epoch`, `Service identities`, `Watchdog alerts`, `Audit records` with next `ML-DSA-65` checkpoint cadence).
* **Overview:** Interactive SVG **Service Access Topology** rendering policy edges, unauthorized lateral-movement hops, and clickable service nodes paired with a **Selected service node** inspector (`Revoke credentials` / `Re-enroll replacement`), **Send encrypted message** form (`POST /api/v1/gateway/transfer`), and **Watchdog security alerts** table.
* **Identities & Lifecycle:** Epoch grace-window inspector (`GET /api/v1/authority/epoch-check`), `.qvbak` signed backup creation, restoration, and 1-byte tamper verification (`POST /api/v1/probes/backup-tamper`), plus responsive service registry with credential revocation and replacement re-enrollment modals (`<dialog>`).
* **Security Lab:** Live cryptographic protocol probes (anti-replay bitmask rejection, recipient AAD substitution `InvalidTag`, peer-bound session resumption hijack & single-use replay) alongside deterministic watchdog tests (multi-hop lateral movement, `PRIV_ESC_001` vs. `Admin` context rules, and `±5s` clock-skew flush verification).
* **Audit Ledger:** Filterable canonical `SHA-256` ledger view explaining periodic `ML-DSA-65` checkpointing (`checkpoint_signature: null` on intermediate chained records) with clickable row modals inspecting full record JSON payloads.
