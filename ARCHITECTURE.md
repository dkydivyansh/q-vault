# Q-Vault Sentinel — System Architecture & Technical Specification

> Return to [`README.md`](README.md) for the executive overview, cryptographic rationale, FIPS 204 mapping, and enterprise use cases.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [End-to-End Operational Flows](#2-end-to-end-operational-flows)
3. [Security Controls & Verification Matrix](#3-security-controls--verification-matrix)
4. [Repository Structure](#4-repository-structure)
5. [Environment Setup & Execution](#5-environment-setup--execution)
6. [Evaluation Metrics & Resilience Testing](#6-evaluation-metrics--resilience-testing)
7. [Engineering & Security Constraints](#7-engineering--security-constraints)

---

## 1. System Architecture

Q-Vault Sentinel integrates cryptographic identity lifecycle management, encrypted transport, tamper-evident telemetry, and deterministic threat containment into a unified four-plane architecture:

```text
+------------------------------------------------------------------------------+
|                        CONTROL PLANE (src/authority.py)                      |
|  [ Identity Registry ]  [ Rotation Scheduler ]  [ Revocation Broadcaster ]   |
|            |                      |                         |                |
|            +----------------------+-------------------------+                |
|                                   v                                          |
|              [ SQLite WAL State Store ] <---> [ Signed/Encrypted Backups ]   |
+-------------------------|-----------------------------------+----------------+
                          | Signed ML-DSA Epochs &            ^
                          | Revocation Notices                | Automated
                          v                                   | Revocation
+---------------------------------------------------+         |
|              DATA PLANE (src/gateway.py)          |         |
|                                                   |         |
|  +-------------------+        +-----------------+ |         |
|  | Service Node A    |  E2EE  | Service Node B  | |         |
|  | (e.g., App/Auth)  | =====> | (e.g., Vault/DB)| |         |
|  | [PQC Gateway A]   | ML-KEM | [PQC Gateway B] | |         |
|  +--------+----------+ +GCM   +--------+--------+ |         |
|           |                            |          |         |
+-----------|----------------------------|----------+         |
            | Canonical Escaped JSON     |                    |
            v                            v                    |
+---------------------------------------------------+         |
|            TELEMETRY PLANE (src/ledger.py)        |         |
|  [ Strict JSON Escaper ] -> [ SHA-256 Hash Chain ]|         |
|  [ ML-DSA Checkpoint Signer ] -> [ audit.jsonl ]  |         |
+-------------------------|-------------------------+         |
                          | Stream Events                     |
                          v                                   |
+---------------------------------------------------+         |
|       DETECTION & RESPONSE (src/detector.py)      |         |
|  1. Clock-Skew Reorder Buffer (+/- 5s window)     |         |
|  2. Context & Privilege Rule Engine (Zero AI/ML)  |---------+
|  3. Directed Service-Access Graph (Lateral Move)  |
|  4. Metrics Reporter (F1, Median TTA, FP/1000)    |
+-------------------------|-------------------------+
                          v
+---------------------------------------------------+
|            OPERATOR CONSOLE (src/console.py)      |
|  Live Alerts | Key Status | Chain Verifier | CLI  |
+---------------------------------------------------+
```

### Core Subsystem Responsibilities

| Subsystem | Module | Responsibilities |
| :--- | :--- | :--- |
| **Cryptographic Engine** | `src/crypto_engine.py` | Provides hybrid `X25519 + ML-KEM-768` key encapsulation, `ML-DSA-65` signatures with domain separation, `HKDF-SHA256` session derivation, `AES-256-GCM` chunk encryption with AAD binding, and resumption ticket sealing. |
| **Key & Identity Authority** | `src/authority.py` | Manages service-node identity registration, epoch rotation with configurable grace periods, signed revocation broadcasts, propagation latency tracking, SQLite WAL state persistence, and encrypted, signed key backups. |
| **Quantum-Safe Node Gateway** | `src/gateway.py` | Acts as the data-plane service proxy handling forward-secret handshakes, sliding-bitmask anti-replay enforcement, chunked payload transfer and ordered reassembly, and peer-bound session resumption. |
| **Tamper-Evident Audit Ledger** | `src/ledger.py` | Serializes all telemetry as strict single-line canonical JSON, chains records via `SHA-256`, and generates periodic `ML-DSA-65` signed checkpoints for offline integrity verification. |
| **Deterministic Watchdog** | `src/detector.py` | Buffers out-of-order events within a configurable clock-skew window, evaluates context-aware privilege rules and directed service-graph policies without AI/ML, computes detection metrics, and triggers automated key revocation. |
| **Operator Console** | `src/console.py` | Provides a Click and Rich terminal interface for node status inspection, live telemetry monitoring, offline hash-chain verification, manual node revocation, and an end-to-end operational walkthrough. |

---

## 2. End-to-End Operational Flows

### 2.1 Flow A: Quantum-Safe Message & File Transfer

1. **Forward-Secret Handshake:** Initiating and responding nodes generate ephemeral `X25519` keys alongside `ML-KEM-768` encapsulation, exchange public parameters inside an `ML-DSA-65`-authenticated transcript (`ctx="qvault-handshake-v1"`), derive a session key via `HKDF-SHA256`, and wipe ephemeral secrets immediately after derivation.
2. **Recipient-Bound Chunk Encryption:** Payloads are segmented into indexed chunks (`msg_id`, `chunk_idx`, `total_chunks`) and encrypted with `AES-256-GCM`. Transport metadata (`sender_id`, `recipient_id`, `key_epoch`, `seq_num`) is bound as Associated Data (AAD), ensuring any recipient substitution or header modification fails tag verification immediately.
3. **Anti-Replay & Delivery Under Loss/Reordering:** Receiving gateways enforce a 1,024-slot sliding sequence bitmask (dropping duplicate or stale packets immediately) and buffer out-of-order chunks until complete. Incomplete or corrupted transfers time out, are discarded, and emit an explicit delivery-failure record.
4. **Peer-Bound Session Resumption:** Resumption tickets bind `session_id`, `authenticated_peer_id`, `epoch`, and `expiry` under an `AES-256-GCM`-encrypted, `ML-DSA-65`-signed envelope (`ctx="qvault-resumption-v1"`). Presenting a captured ticket under a different peer identity fails signature and peer-binding validation prior to session restoration.

### 2.2 Flow B: Zero-Downtime Rotation, Revocation & Crash Recovery

1. **Epoch Rotation with Grace Window:** Rotating from `epoch N` to `epoch N+1` opens a policy-defined grace window (default `30s` in `config/policy.yaml`). In-flight transfers encrypted under the prior epoch remain accepted until the grace cutoff timestamp, after which legacy epochs are strictly rejected.
2. **Cross-Node Revocation & Re-Enrollment:** Revoking a compromised node increments the monotonic `revocation_epoch`, emits an `ML-DSA-65`-signed revocation notice (`ctx="qvault-revoke-v1"`), collects node acknowledgments, and records enforcement latency up to the final acknowledging node. Authorized operators can re-enroll a new identity keypair for the host while unaffected services continue operating uninterrupted.
3. **Crash Recovery & Backup Integrity:** Every identity registration, rotation, and revocation executes inside an atomic SQLite WAL transaction (`BEGIN IMMEDIATE ... COMMIT`). An unexpected process termination mid-rotation recovers cleanly to the last committed epoch while preserving all committed revocations. Key backups are encrypted with an environment-injected Master Key Encryption Key (KEK), checksummed via `SHA-256`, and signed with `ML-DSA-65` (`ctx="qvault-backup-v1"`); any single-bit modification causes signature verification to fail prior to decryption.

### 2.3 Flow C: Injection-Proof Telemetry & Deterministic Watchdog

1. **Tamper-Evident Audit Logging:** Every event is canonicalized with `json.dumps(..., sort_keys=True, ensure_ascii=True, separators=(",", ":"))` so untrusted input (such as embedded newlines or forged JSON fragments) remains strictly escaped inside a single JSON field. Records link via `SHA-256(prev_hash || canonical_json)` with periodic `ML-DSA-65` checkpoints (`ctx="qvault-log-v1"`) verifiable offline.
2. **Clock-Skew Reordering:** Incoming events pass through a sliding reorder buffer supporting clock offsets up to $\pm 5\text{ seconds}$ (configurable in `config/policy.yaml`). Dependent events falling within the skew uncertainty window are processed and explicitly tagged `ordering_uncertain: true`.
3. **Rule & Graph Lateral-Movement Detection:** A deterministic rule engine validates privilege-changing actions against authorized administrative groups and approved maintenance windows, while a directed service-access graph checks each service-to-service transition against permitted edges. Unauthorized privilege escalation or lateral movement generates an alert naming the actor, services, event IDs, and violated rule or path, and triggers automated key revocation when severity exceeds the critical threshold.

---

## 3. Security Controls & Verification Matrix

| Security Control Objective | Implementation Module | Verification Proof |
| :--- | :--- | :--- |
| **1. Key Rotation & Cutoff** | `src/authority.py`, `src/gateway.py` | Active transfers succeed during the 30s grace window; expired epochs are rejected immediately after cutoff. |
| **2. Cross-Node Revocation** | `src/authority.py`, `src/gateway.py` | Revoked keys are rejected across all service nodes; last-node acknowledgment latency is recorded; legitimate owners re-enroll cleanly. |
| **3. Crash Recovery** | `src/authority.py` | Abrupt termination (`SIGKILL`) mid-rotation recovers to a consistent key version; revoked keys stay blocked; protected data remains accessible. |
| **4. Backup Integrity** | `src/authority.py` | Any single-bit modification in an encrypted backup fails `ML-DSA` + `AES-GCM` verification and aborts restoration. |
| **5. Log Integrity** | `src/ledger.py` | Newline and JSON injection payloads remain escaped inside single records; modifying or deleting any entry fails `verify-log`. |
| **6. Routine vs. Suspicious Activity** | `src/detector.py` | Context-aware rules distinguish approved administrative tasks from unauthorized escalation; outputs F1, median TTA, and FP/1,000 events. |
| **7. Lateral Movement Detection** | `src/detector.py` | Directed graph flags unauthorized service paths even under valid credentials, identifying actor, services, event IDs, and violated path. |
| **8. Clock-Skew Resilience** | `src/detector.py` | Processes out-of-order events within $\pm 5\text{ s}$ clock skew; flags ambiguous causal order with `ordering_uncertain: true`. |
| **9. Replay & Recipient Binding** | `src/crypto_engine.py`, `src/gateway.py` | Duplicate sequence packets are dropped; modified recipient metadata fails `AES-256-GCM` AAD tag verification. |
| **10. Forward Secrecy** | `src/crypto_engine.py`, `src/gateway.py` | Compromise of a long-term `ML-DSA` identity key cannot decrypt previously captured session transcripts. |
| **11. Delivery Under Loss/Reordering** | `src/gateway.py` | Out-of-order valid chunks reassemble cleanly; incomplete or corrupted transfers are discarded with logged delivery failures. |
| **12. Peer-Bound Session Resumption** | `src/gateway.py` | Resumption tickets bind authenticated `peer_id`; presenting a captured session ID under a different identity is rejected. |

---

## 4. Repository Structure

```text
q-vault/
├── README.md                     # Executive overview, FIPS 204 mapping, enterprise use cases & references
├── ARCHITECTURE.md               # System architecture, protocol flows, control matrix, setup & constraints
├── AGENTS.md                     # Repository-wide engineering terminology and documentation rules
├── requirements.txt              # Pinned, vetted Python dependencies (zero AI/ML packages)
├── config/
│   ├── policy.yaml               # Service graph policy, 30s rotation grace window, +/- 5s skew tolerance
│   └── .env.example              # Environment variable template (zero hardcoded secrets)
├── data/                         # Runtime database, ledger logs, and encrypted backup artifacts
├── docs/
│   └── refrences/
│       └── nist.fips.204.pdf     # NIST FIPS 204 (ML-DSA) reference specification
├── src/
│   ├── crypto_engine.py          # Hybrid X25519+ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF, tickets
│   ├── authority.py              # Key lifecycle, epoch cutoff, revocation broadcast, WAL SQLite, backups
│   ├── gateway.py                # Data-plane proxy: PFS handshake, AAD binding, anti-replay, chunking
│   ├── ledger.py                 # Canonical JSON logger, SHA-256 hash chain, ML-DSA checkpoint verifier
│   ├── detector.py               # Clock-skew buffer, context rules, directed service graph, metrics
│   └── console.py                # Operator CLI & live status dashboard
└── tests/                        # Automated verification and fault-tolerance test suite
```

---

## 5. Environment Setup & Execution

### Prerequisites

* **Operating System:** Linux (Ubuntu 22.04/24.04, Debian, Arch), macOS, or Windows
* **Python:** `3.11+` (verified on Python `3.12`)
* **Network Isolation:** All cryptographic operations, key persistence, logging, and threat detection run locally without external APIs or cloud dependencies.

### Step 1: Install Dependencies

```bash
git clone <repository-url>
cd q-vault

python3 -m venv .venv
source .venv/bin/activate   # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Configure Runtime Secrets

Generate a 32-byte Master Key Encryption Key (KEK) for sealing key backups and authority state, and inject it via environment variables (never commit `.env` files containing live keys):

```bash
cp config/.env.example .env
export QVAULT_MASTER_KEK=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

On Windows PowerShell:

```powershell
Copy-Item config\.env.example .env
$env:QVAULT_MASTER_KEK = python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Step 3: Operate via the Operator Console

The CLI (`src/console.py`) provides direct inspection, verification, revocation, and operational walkthrough commands:

```bash
# Inspect registered service nodes, active key epoch, and audit chain head
python3 -m src.console status --db-path ./data/authority.db --ledger-path ./data/audit.jsonl

# Launch the live terminal monitoring dashboard
python3 -m src.console watch --db-path ./data/authority.db --ledger-path ./data/audit.jsonl

# Verify SHA-256 hash-chain integrity offline
python3 -m src.console verify-log --ledger-path ./data/audit.jsonl

# Execute manual emergency key revocation for a compromised node
python3 -m src.console revoke NodeA --db-path ./data/authority.db --reason "credential compromise"

# Run the interactive end-to-end operational walkthrough
python3 -m src.console demo
```

### Step 4: Programmatic Control-Plane & Data-Plane Integration

Core subsystems (`src.authority`, `src.gateway`, `src.ledger`, `src.detector`, `src.crypto_engine`) are structured as composable Python modules configured via `config/policy.yaml`, enabling direct embedding into service gateways and automated verification harnesses.

---

## 6. Evaluation Metrics & Resilience Testing

### Automated Verification Suite

Execute the automated test suite across cryptographic protocol guarantees, key lifecycle fault tolerance, log integrity, and deterministic detection:

```bash
pytest -v tests/
```

### Deterministic Detection & Operational Telemetry

`WatchdogDetector` (`src/detector.py`) evaluates labeled event streams in batch or real-time mode and reports structured performance and resilience metrics via `DetectionMetrics` and `get_metrics_report()`:

* **Precision, Recall, and F1 Score:** Classification accuracy across privilege escalation (`PRIV_ESC_001`), lateral movement (`LAT_MOVE_001`), replay (`REPLAY_001`), and revoked-access (`REVOKED_001`) detections.
* **Median Time to Alert (TTA):** Median elapsed seconds from event timestamp/ingestion to alert generation.
* **False Positives per 1,000 Benign Events:** Quantifies rule precision against routine administrative traffic within approved maintenance windows.
* **Clock-Skew Reorder Telemetry:** Reports settled event ordering across the configured $\pm 5\text{ s}$ tolerance window and tracks alerts tagged with `ordering_uncertain: true`.
* **Revocation Propagation Latency (ms):** Measured via `KeyAuthority.get_propagation_stats()` from revocation issuance to final service-node acknowledgment.
* **Fault-Tolerance & Recovery Verification:** Validates SQLite WAL rollback/recovery under interrupted transactions, hard post-cutoff epoch rejection, single-bit backup corruption rejection, and replay/tamper rejection under packet loss and reordering.

---

## 7. Engineering & Security Constraints

Q-Vault Sentinel enforces four non-negotiable engineering constraints across the entire codebase:

1. **Deterministic Detection (Zero AI/ML):** No neural networks, large language models, or opaque statistical classifiers are imported or used anywhere in the system. All alerts derive strictly from explicit rules and directed service-access graph policies, ensuring full auditability and deterministic reproduction.
2. **Vetted Cryptographic Primitives Only:** All post-quantum and classical algorithms (`ML-KEM-768`, `ML-DSA-65`, `X25519`, `AES-256-GCM`, `HKDF-SHA256`, `SHA-256`) are invoked exclusively from `pyca/cryptography` and Python's standard cryptographic interfaces without custom cryptographic math.
3. **Zero Hardcoded Secrets:** Master KEKs, identity seeds, and session keys are never stored in source code or configuration defaults; runtime secrets are generated ephemerally or injected via environment variables.
4. **Strict Key-Usage Separation & Verification Isolation:** Pursuant to NIST FIPS 204 Clause 8, `ML-DSA` signing keys are strictly isolated from `ML-KEM` / `X25519` key-establishment keys, and automated resilience tests operate solely against isolated service fixtures and synthetic event datasets.
