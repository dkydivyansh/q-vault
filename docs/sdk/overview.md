# Q-Vault Sentinel SDK Reference (`src/sdk/`)

> See [`docs/architecture.md`](../architecture.md) for the system architecture and operational flows.

---

## 1. Overview

The `src.sdk` package exposes composable, thread-safe Python primitives across five security layers:

1. **Cryptographic Engine:** Hybrid `X25519 + ML-KEM-768` forward-secret key establishment, `ML-DSA-65` signatures with FIPS 204 domain-separation contexts, `HKDF-SHA256`, `AES-256-GCM` chunk encryption with AAD binding, and encrypted/signed resumption ticket helpers.
2. **Key & Identity Authority (`KeyAuthority`):** SQLite WAL-backed identity registry, epoch rotation with configurable grace windows and hard cutoffs, signed revocation broadcasts with propagation acknowledgment tracking, host re-enrollment (`re_enroll_node`), and encrypted/signed key backup and restore.
3. **Quantum-Safe Node Gateway (`NodeGateway`):** Service-node proxy handling authenticated handshakes, per-session 1,024-slot `AntiReplayWindow` tracking (mutated only after `AES-256-GCM` authentication), strict AAD equality validation (`sender`, `recipient`, `epoch`, `seq`), ordered chunk reassembly, single-use peer-bound session resumption, and cross-node revocation enforcement.
4. **Tamper-Evident Audit Ledger (`AuditLedger`):** Append-only, `fsync`-persisted canonical JSONL logging (`ensure_ascii=True`, `sort_keys=True`), `SHA-256` hash chaining, periodic `ML-DSA-65` checkpoints, and chain verification (`verify_chain()`).
5. **Deterministic Watchdog (`WatchdogDetector`):** Clock-skew reorder buffering (`ClockSkewBuffer`), directed service-access policy graph (`ServiceAccessGraph`), context-aware rule evaluation (`RuleEngine`), structured alert attribution (`actor`, `services_involved`, `event_ids`, `violated_rule`, `violated_path`), batch evaluation metrics (`DetectionMetrics`), and automated revocation callback integration.

---

## 2. Protocol Context Strings (FIPS 204 Domain Separation)

All `ML-DSA-65` signing operations enforce explicit `context` tags (`|ctx| <= 255` bytes) so signatures cannot be replayed across protocol boundaries:

| Context Constant | Context Value | Purpose |
| :--- | :--- | :--- |
| `CTX_HANDSHAKE` | `qvault-handshake-v1` | Hybrid handshake transcript authentication |
| `CTX_EPOCH` | `qvault-epoch-v1` | Key rotation epoch announcements |
| `CTX_REVOKE` | `qvault-revoke-v1` | Cross-node emergency key revocation directives |
| `CTX_BACKUP` | `qvault-backup-v1` | Encrypted authority backup and helper ticket sealing |
| `CTX_LOG` | `qvault-log-v1` | Audit ledger checkpoint signatures |
| `CTX_RESUMPTION` | `qvault-resumption-v1` | Node gateway peer-bound session resumption tickets |

---

## 3. Public Package Exports

Import core SDK types and functions directly from `src.sdk`:

```python
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
```

* **Key Encoding:** Public keys issued by `KeyAuthority` use fixed raw FIPS 203/204/RFC 7748 sizes (`1,952` bytes for `ML-DSA-65`, `1,184` bytes for `ML-KEM-768`, `32` bytes for `X25519`). `load_mldsa_public_key` and `load_mlkem_public_key` transparently accept both raw and DER SubjectPublicKeyInfo formats.
* **Key-Usage Separation:** The authority signing keypair (`authority_keys`) and audit ledger checkpoint keypair (`ledger_keys`) are persisted separately in SQLite WAL under `AES-256-GCM` encryption keyed by `QVAULT_MASTER_KEK`.
