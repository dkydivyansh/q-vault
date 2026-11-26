# Q-Vault Sentinel SDK (`src/sdk/`)

> Return to [`docs/architecture.md`](../architecture.md) for the four-plane system architecture and operational flows.

---

## 1. Package Overview

The `src.sdk` package provides a modular Python security SDK backed by `pyca/cryptography` (`>= 50.0.1`), SQLite in Write-Ahead Log (WAL) mode, and deterministic rule/graph telemetry analysis (zero AI/ML components).

All public classes, dataclasses, constants, and functions are re-exported at package level:

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

### Detailed SDK References

* **[Cryptographic Engine Reference](cryptography.md):** Hybrid `X25519 + ML-KEM-768` handshakes, `ML-DSA-65` signatures, `AES-256-GCM` chunking with AAD binding, `HKDF-SHA256`, key serialization, and resumption tickets.
* **[Key Authority & Node Gateway Reference](authority-and-gateway.md):** `KeyAuthority` (SQLite WAL identity store, epoch grace/cutoff rotation, signed revocations, encrypted backups) and `NodeGateway` (sessions, per-session anti-replay, chunk reassembly, resumption).
* **[Audit Ledger & Watchdog Detector Reference](ledger-and-detector.md):** `AuditLedger` (`SHA-256` hash chaining, canonical JSONL escaping, `ML-DSA-65` checkpoints) and `WatchdogDetector` (clock-skew reorder buffer, directed service graph, rule engine, evaluation metrics).

---

## 2. Protocol Context Strings (FIPS 204 Domain Separation)

Every `ML-DSA-65` signature uses a domain-separated `context` byte string (`|ctx| <= 255` bytes) so signatures valid in one protocol step cannot verify in another:

| Constant | Value | Scope |
| :--- | :--- | :--- |
| `CTX_HANDSHAKE` | `b"qvault-handshake-v1"` | Hybrid handshake transcript authentication |
| `CTX_EPOCH` | `b"qvault-epoch-v1"` | Key-rotation epoch announcements |
| `CTX_REVOKE` | `b"qvault-revoke-v1"` | Cross-node revocation notices |
| `CTX_BACKUP` | `b"qvault-backup-v1"` | Authority backups and low-level ticket sealing |
| `CTX_LOG` | `b"qvault-log-v1"` | Audit ledger checkpoint signatures |
| `CTX_RESUMPTION` | `b"qvault-resumption-v1"` | Gateway session resumption tickets |

---

## 3. End-to-End SDK Usage Example

```python
import os
import secrets
import tempfile
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

with tempfile.TemporaryDirectory() as workdir:
    master_kek_hex = secrets.token_hex(32)
    authority = KeyAuthority(
        db_path=os.path.join(workdir, "authority.db"),
        master_kek_hex=master_kek_hex,
        grace_period_seconds=30.0,
    )

    kp_portal = generate_identity_keypair("WebPortal")
    kp_auth = generate_identity_keypair("Auth")
    pub_portal = serialize_public_keys(kp_portal)
    pub_auth = serialize_public_keys(kp_auth)

    authority.register_node(
        "WebPortal",
        pub_portal["signing_public"],
        pub_portal["kem_public"],
        pub_portal["x25519_public"],
    )
    authority.register_node(
        "Auth",
        pub_auth["signing_public"],
        pub_auth["kem_public"],
        pub_auth["x25519_public"],
    )

    ledger_key = authority.get_or_create_ledger_signing_key()
    ledger = AuditLedger(
        ledger_path=os.path.join(workdir, "audit.jsonl"),
        signing_key=ledger_key,
        verify_key=ledger_key.public_key(),
        checkpoint_interval=50,
    )

    gw_portal = NodeGateway(
        "WebPortal",
        serialize_private_keys(kp_portal),
        authority_client=authority,
        ledger=ledger,
    )
    gw_auth = NodeGateway(
        "Auth",
        serialize_private_keys(kp_auth),
        authority_client=authority,
        ledger=ledger,
    )

    gw_portal.register_peer(
        PeerInfo("Auth", pub_auth["signing_public"], pub_auth["kem_public"], pub_auth["x25519_public"])
    )
    gw_auth.register_peer(
        PeerInfo("WebPortal", pub_portal["signing_public"], pub_portal["kem_public"], pub_portal["x25519_public"])
    )

    kem_ct, eph_pub, sig, sid_a = gw_portal.initiate_handshake("Auth", epoch=authority.current_epoch)
    sid_b = gw_auth.complete_handshake("WebPortal", kem_ct, eph_pub, sig, epoch=authority.current_epoch)

    tx = gw_portal.send_message(sid_a, b"Authorized session payload", "Auth")
    chunk = tx.encrypted_chunks[0]
    plaintext = gw_auth.receive_chunk(
        sid_b, chunk["nonce"], chunk["ciphertext"], chunk["aad"], chunk["seq_num"]
    )
    assert plaintext == b"Authorized session payload"
    assert ledger.verify_chain()["ok"] is True
    authority.close()
```
