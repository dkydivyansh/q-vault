# Q-Vault Sentinel — System Architecture

> Return to [`README.md`](../README.md) for the executive overview, cryptographic rationale, FIPS 204 mapping, and enterprise use cases.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [End-to-End Operational Flows](#2-end-to-end-operational-flows)
3. [Security Controls & Verification Matrix](#3-security-controls--verification-matrix)
4. [Repository Structure](#4-repository-structure)
5. [Engineering & Security Constraints](#5-engineering--security-constraints)
6. [Related Documentation](#6-related-documentation)

---

## 1. System Architecture

Q-Vault Sentinel integrates cryptographic identity lifecycle management, encrypted transport, tamper-evident telemetry, and deterministic threat containment into a unified four-plane architecture:

```text
+------------------------------------------------------------------------------+
|                            CONTROL PLANE (src/sdk/)                          |
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
|                              DATA PLANE (src/sdk/)|         |
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
|                         TELEMETRY PLANE (src/sdk/)|         |
|  [ Strict JSON Escaper ] -> [ SHA-256 Hash Chain ]|         |
|  [ ML-DSA Checkpoint Signer ] -> [ Audit Store ]  |         |
+-------------------------|-------------------------+         |
                          | Stream Events                     |
                          v                                   |
+---------------------------------------------------+         |
|                  DETECTION & RESPONSE (src/sdk/)  |         |
|  1. Clock-Skew Reorder Buffer (+/- 5s window)     |         |
|  2. Context & Privilege Rule Engine (Zero AI/ML)  |---------+
|  3. Directed Service-Access Graph (Lateral Move)  |
|  4. Metrics Reporter (F1, Median TTA, FP/1000)    |
+-------------------------|-------------------------+
                          v
+---------------------------------------------------+
|         APPLICATION & CONSOLE LAYER (src/app/)    |
|  Control Plane API | Service Nodes | Web Console  |
|  Operator CLI & Telemetry Runner                  |
+---------------------------------------------------+
```

---

## 2. End-to-End Operational Flows

### 2.1 Flow A: Quantum-Safe Message & File Transfer

1. **Forward-Secret Handshake:** Initiating and responding service nodes generate ephemeral `X25519` keys alongside `ML-KEM-768` encapsulation, exchange public parameters inside an `ML-DSA-65`-authenticated transcript (`ctx="qvault-handshake-v1"`), derive a session key via `HKDF-SHA256`, and clear ephemeral key references immediately after derivation.
2. **Recipient-Bound Chunk Encryption:** Payloads are segmented into indexed chunks (`msg_id`, `chunk_idx`, `total_chunks`) and encrypted with `AES-256-GCM`. Transport metadata (`sender_id`, `recipient_id`, `key_epoch`, `seq_num`) is bound as Associated Data (AAD) and verified on receipt alongside strict sender, recipient, epoch, and sequence equality checks.
3. **Anti-Replay & Delivery Under Loss/Reordering:** Each active session enforces an isolated 1,024-slot sliding sequence bitmask. Read-only replay prechecks drop duplicates before decryption, and the bitmask mutates only after `AES-256-GCM` tag authentication succeeds. Out-of-order chunks buffer until complete; incomplete or corrupted transfers time out, are discarded, and log a delivery failure.
4. **Peer-Bound Session Resumption:** Resumption tickets bind a single-use `jti`, `session_id`, `authenticated_peer_id`, `epoch`, and `expiry` inside an `AES-256-GCM`-encrypted, `ML-DSA-65`-signed envelope (`ctx="qvault-resumption-v1"`). Presenting a captured ticket under a different peer identity or replaying a consumed ticket fails validation before session restoration.

### 2.2 Flow B: Zero-Downtime Rotation, Revocation & Crash Recovery

1. **Epoch Rotation with Grace Window:** Rotating from `epoch N` to `epoch N+1` opens a policy-defined grace window (default `30s` in `config/`). In-flight transfers encrypted under the prior epoch remain accepted until the grace cutoff timestamp, after which legacy epochs are strictly rejected across all service nodes.
2. **Cross-Node Revocation & Re-Enrollment:** Revoking a compromised node increments the monotonic `revocation_epoch`, broadcasts an `ML-DSA-65`-signed revocation notice (`ctx="qvault-revoke-v1"`), collects node acknowledgments, and records enforcement latency up to the final acknowledging node. Revoked keys remain rejected across crashes and restarts, while authorized operators can re-enroll a new host identity without disrupting unaffected services.
3. **Crash Recovery & Backup Integrity:** Every registration, rotation, and revocation executes inside an atomic SQLite WAL transaction (`BEGIN IMMEDIATE ... COMMIT`). Abrupt process termination mid-rotation recovers cleanly to the last committed epoch while preserving all revocations and persisted ledger signing keys. Backups are encrypted with an environment-injected Master Key Encryption Key (KEK), checksummed via `SHA-256`, and signed with `ML-DSA-65` (`ctx="qvault-backup-v1"`); any single-bit modification fails signature verification before decryption.

### 2.3 Flow C: Injection-Proof Telemetry & Deterministic Watchdog

1. **Tamper-Evident Audit Logging:** Every event is canonicalized with `json.dumps(..., sort_keys=True, ensure_ascii=True, separators=(",", ":"))` so untrusted input remains strictly escaped inside a single JSON field. Records link via `SHA-256(prev_hash || canonical_json)` with periodic `ML-DSA-65` checkpoints (`ctx="qvault-log-v1"`) verifiable offline.
2. **Clock-Skew Reordering:** Incoming events pass through a sliding reorder buffer supporting clock offsets up to $\pm 5\text{ seconds}$ (configurable in `config/`). Dependent events within the skew uncertainty window are processed and explicitly tagged `ordering_uncertain: true`.
3. **Rule & Graph Lateral-Movement Detection:** A deterministic rule engine validates privilege-changing actions against administrative roles and maintenance windows, while a directed service-access graph checks each transition against permitted edges. Unauthorized privilege escalation, replay events, or lateral movement emit alerts identifying `actor`, `services_involved`, contributing `event_ids`, `violated_rule`, and `violated_path`, automatically triggering cross-node key revocation on critical detections.

---

## 3. Security Controls & Verification Matrix

| Security Control Objective | Implemented In | Verified By |
| :--- | :--- | :--- |
| **1. Key Rotation & Cutoff** | `src/sdk/` | `tests/` (grace window acceptance and post-cutoff rejection across epoch transitions) |
| **2. Cross-Node Revocation** | `src/sdk/`, `src/app/` | `tests/` (signed broadcast enforcement, propagation latency telemetry, clean re-enrollment) |
| **3. Crash & Restart Recovery** | `src/sdk/`, `src/app/` | `tests/` (abrupt process termination WAL rollback and post-restart revocation/ledger persistence) |
| **4. Backup Integrity** | `src/sdk/` | `tests/` (single-bit backup modification rejected before decryption) |
| **5. Log Integrity** | `src/sdk/` | `tests/` (newline injection escaping, `SHA-256` chain & `ML-DSA-65` checkpoint verification) |
| **6. Routine vs. Suspicious Activity** | `src/sdk/`, `src/app/` | `tests/` (admin/maintenance suppression vs. escalation detection; F1, median TTA, FP/1,000) |
| **7. Lateral Movement Detection** | `src/sdk/`, `src/app/` | `tests/` (directed graph violations naming identity, services, event IDs, violated path & auto-revoke) |
| **8. Clock-Skew Resilience** | `src/sdk/` | `tests/` (out-of-order buffering within $\pm 5\text{ s}$ and `ordering_uncertain: true` attribution) |
| **9. Replay & Recipient Binding** | `src/sdk/` | `tests/` (per-session anti-replay isolation, AAD equality enforcement, tag failure on re-routing) |
| **10. Forward Secrecy** | `src/sdk/` | `tests/` (distinct ephemeral session keys; long-term identity key cannot decrypt past sessions) |
| **11. Delivery Under Loss/Reordering** | `src/sdk/` | `tests/` (out-of-order chunk reassembly and timeout discard for incomplete transfers) |
| **12. Peer-Bound Session Resumption** | `src/sdk/`, `src/app/` | `tests/` (peer identity binding and single-use ticket replay rejection over SDK and HTTP) |

---

## 4. Repository Structure

```text
q-vault/
├── config/                  # Policy definitions and environment variable templates
├── data/                    # Runtime SQLite WAL database, audit ledger, and encrypted backups
├── docs/                    # Architecture, SDK, operations, verification, and threat-model documentation
│   ├── refrences/           # Reference cryptographic specifications
│   └── sdk/                 # Security SDK developer documentation
├── src/
│   ├── sdk/                 # Core post-quantum cryptography, authority, gateway, ledger, and detector SDK
│   └── app/                 # Closed-loop runtime, FastAPI control/service endpoints, web console, and CLI
└── tests/                   # Automated protocol, lifecycle, telemetry, and HTTP integration test suite
```

---

## 5. Engineering & Security Constraints

Q-Vault Sentinel enforces four engineering constraints across the codebase:

1. **Deterministic Detection (Zero AI/ML):** No neural networks, large language models, or opaque statistical classifiers are imported or used anywhere in the system. All alerts derive strictly from explicit rules and directed service-access graph policies.
2. **Vetted Cryptographic Primitives Only:** All post-quantum and classical algorithms (`ML-KEM-768`, `ML-DSA-65`, `X25519`, `AES-256-GCM`, `HKDF-SHA256`, `SHA-256`) are invoked exclusively from `pyca/cryptography` and Python's standard cryptographic interfaces.
3. **Zero Hardcoded Secrets:** Master KEKs, identity seeds, and session keys are never stored in source code or configuration defaults; runtime secrets are generated ephemerally or injected via environment variables.
4. **Strict Key-Usage Separation & Verification Isolation:** Pursuant to NIST FIPS 204 Clause 8, `ML-DSA` signing keys are strictly segregated from `ML-KEM` / `X25519` key-establishment keys, and automated resilience tests operate solely against isolated service fixtures and synthetic event datasets.

---

## 6. Related Documentation

* **[SDK Overview](sdk/overview.md)** — Installation, `src/sdk/` import guide, domain-separation contexts, and end-to-end integration flow
* **[SDK Cryptographic Engine API](sdk/cryptography.md)** — Identity generation, `ML-DSA-65` signing, `X25519 + ML-KEM-768` handshakes, and `AES-256-GCM` chunk envelopes
* **[SDK Authority & Gateway API](sdk/authority-and-gateway.md)** — `KeyAuthority` lifecycle/WAL persistence, `NodeGateway` transport, anti-replay, and resumption tickets
* **[SDK Ledger & Watchdog API](sdk/ledger-and-detector.md)** — `AuditLedger` canonical hash chain and `WatchdogDetector` deterministic detection & metrics
* **[Operations, CLI & HTTP API](operations.md)** — Environment setup, configuration, operator CLI, REST API endpoints, and Web Console (`src/app/`)
* **[Verification & Benchmark Results](testing.md)** — Automated `tests/` case catalog, isolation fixtures, benchmark API, and observed metrics
* **[Threat Model & Limitations](threat-model.md)** — Adversary capabilities, trust boundaries, and explicit engineering limitations
