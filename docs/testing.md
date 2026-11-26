# Verification & Benchmark Results (`tests/`)

> Return to [`docs/architecture.md`](architecture.md) for system architecture and security controls.

---

## 1. Automated Verification Suite

Execute the full `pytest` verification suite covering cryptographic protocol guarantees, lifecycle fault tolerance, log integrity, HTTP service integration, and deterministic detection:

```bash
python3 -m pytest tests/ -v --tb=short
```

All **25 tests** across `tests/` verify:

* **Cryptographic Protocol Guarantees:** `AES-256-GCM` roundtrip, AAD recipient/sender/epoch/sequence binding enforcement, `ML-DSA-65` sign/verify and domain separation, per-session `AntiReplayWindow` isolation (and pre-authentication read-only check), forward secrecy, out-of-order chunk reassembly, incomplete transfer timeout cleanup, and single-use peer-bound session resumption tickets.
* **Lifecycle & Resilience Guarantees:** Key rotation grace window and hard post-cutoff rejection, cross-node revocation broadcast and acknowledgment latency, host re-enrollment while preserving prior revocations, single-bit backup corruption rejection prior to decryption, SQLite WAL crash recovery across abrupt `os._exit(1)` termination, and persistence of revocations and ledger checkpoint keys across restarts.
* **Telemetry & Deterministic Detection:** Canonical JSON newline-injection escaping, `SHA-256` hash-chain tamper detection, $\pm 5\text{ s}$ clock-skew reordering with `ordering_uncertain: true`, context-aware admin and maintenance-window suppression, directed service-graph lateral movement attribution (`actor`, `services_involved`, contributing `event_ids`, `violated_rule`, `violated_path`), automated revocation callbacks, and batch evaluation metrics.
* **HTTP Application Integration:** End-to-end FastAPI `TestClient` tests across the Web Console UI, service-node handshakes, encrypted transfers, replay rejection, single-use session resumption hijack rejection, lateral-movement auto-revocation, and ledger verification.

---

## 2. Reproducible Benchmark Suite

Run the deterministic benchmark command to collect live timings and detection accuracy on the local host:

```bash
python3 -m src.app.console benchmark
```

### Observed Measurements

Measured on Python `3.12.10` with `cryptography 50.0.1` (Windows x64, local SQLite WAL and `os.fsync` JSONL storage, `config/` defaults):

| Metric | Observed Result | Measurement Scope |
| :--- | :--- | :--- |
| **Configured Rotation Grace Period** | `30.0 s` | Policy rotation grace window enforced pre- and post-cutoff |
| **Hybrid Handshake Latency** (`X25519 + ML-KEM-768 + ML-DSA-65`) | `2.788 ms` median (`1.927 – 6.032 ms`) | 20 full initiator + responder handshakes |
| **AES-256-GCM 64 KB Chunk Roundtrip** | `0.179 ms` median (`333.75 MB/s`) | 50 encrypt + AAD-verified decrypt operations |
| **Cross-Node Revocation Propagation** | `4.997 – 20.714 ms` (`8` nodes acked) | Signed `ML-DSA-65` broadcast to 8 registered service gateways |
| **Audit Ledger Write & Chain Verification** | `455.12 ms` write / `22.53 ms` verify | 200 canonical JSONL records with `fsync` and `ML-DSA-65` checkpoints every 50 entries |
| **Synthetic Workload F1 Score** | `1.0` (`TP=50, FP=0, FN=0, TN=1000`) | 1,050 labeled events (1,000 benign incl. admin/maintenance + 50 multi-vector attacks) |
| **False Positives per 1,000 Benign Events** | `0.0` | Measured across 1,000 benign events (`53.36 ms` total batch runtime) |
| **Median Time to Alert (TTA)** | `4.6107 s` | Includes configured `5.0 s` clock-skew reorder window hold (`61` `ordering_uncertain` alerts, `9` auto-revocations) |
