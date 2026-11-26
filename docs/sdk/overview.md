# Q-Vault Sentinel SDK (`src/sdk/`)

> Return to [`docs/architecture.md`](../architecture.md) for the four-plane system architecture and operational flows.

---

## 1. Overview & Public Package Inventory (49 Exports)

The `src.sdk` package exposes 49 public symbols across five self-contained modules built on `pyca/cryptography` (`>= 50.0.1`), SQLite in Write-Ahead Log (WAL) mode, and deterministic rule/graph analysis (zero AI/ML components).

### SDK Guides

* **[Cryptographic Engine Reference](cryptography.md):** Key formats/sizes (`ML-DSA-65`, `ML-KEM-768`, `X25519`, `AES-256-GCM`, `HKDF-SHA256`), context constants, hybrid handshakes, chunk AAD binding, signing, symmetric encryption, and low-level ticket helpers.
* **[Key Authority & Node Gateway Reference](authority-and-gateway.md):** `KeyAuthority` (SQLite WAL registration, epoch grace/cutoff rotation, cross-node revocations, `.qvbak` backups, re-enrollment) and `NodeGateway` (chunked transport, `AntiReplayWindow`, reassembly, single-use resumption tickets).
* **[Audit Ledger & Watchdog Detector Reference](ledger-and-detector.md):** `AuditLedger` (injection-proof canonical JSONL, `SHA-256` hash chaining, `ML-DSA-65` checkpoints) and `WatchdogDetector` (`ClockSkewBuffer`, `ServiceAccessGraph`, `RuleEngine`, `DetectionMetrics`).

### Export Inventory by Module

| Module | Public Classes, Dataclasses & Constants | Public Functions & Capabilities | Detailed Guide |
| :--- | :--- | :--- | :--- |
| **Cryptographic Engine** | `HybridKeyPair`, `SessionKeys`, `EncryptedChunk`, `HandshakeResult`, `CTX_HANDSHAKE`, `CTX_EPOCH`, `CTX_REVOKE`, `CTX_BACKUP`, `CTX_LOG`, `CTX_RESUMPTION` | `generate_identity_keypair`, `serialize_public_keys`, `serialize_private_keys`, `load_mldsa_public_key`, `load_mlkem_public_key`, `perform_handshake_initiator`, `perform_handshake_responder`, `encrypt_chunk`, `decrypt_chunk`, `sign_data`, `verify_signature`, `aes_gcm_encrypt`, `aes_gcm_decrypt`, `derive_key`, `sha256_hash`, `generate_session_resumption_ticket`, `validate_resumption_ticket` | [cryptography.md](cryptography.md) |
| **Key & Identity Authority** | `KeyAuthority`, `NodeRecord`, `RotationEpoch`, `RevocationNotice` | Registration, `re_enroll_node`, scheduled rotation with grace cutoff (`rotate_keys`, `is_epoch_valid`), signed revocation broadcast & ack latency tracking, `.qvbak` backup/restore, WAL recovery | [authority-and-gateway.md](authority-and-gateway.md) |
| **Quantum-Safe Node Gateway** | `NodeGateway`, `PeerInfo`, `AntiReplayWindow`, `ActiveSession`, `TransferResult` | Peer registry, signed revocation enforcement, hybrid handshake, 64 KiB chunking & out-of-order reassembly, 1,024-bit sliding anti-replay window, single-use peer-bound resumption tickets | [authority-and-gateway.md](authority-and-gateway.md) |
| **Tamper-Evident Audit Ledger** | `AuditLedger`, `LogEntry`, `GENESIS_HASH`, `DEFAULT_CHECKPOINT_INTERVAL` | Canonical `sort_keys=True, ensure_ascii=True` JSONL logging with `os.fsync()`, `SHA-256` chaining, periodic `ML-DSA-65` checkpoints, chain & signature verification, real-time sinks | [ledger-and-detector.md](ledger-and-detector.md) |
| **Zero-AI Watchdog Detector** | `WatchdogDetector`, `ClockSkewBuffer`, `ServiceAccessGraph`, `RuleEngine`, `DetectionMetrics`, `LogEvent`, `Alert`, `AlertType`, `Severity` | `±5s` clock-skew reordering (`ordering_uncertain` tagging), privilege-escalation & revoked-access rules, directed service-graph lateral-movement containment, batch F1/TTA/FP metrics | [ledger-and-detector.md](ledger-and-detector.md) |

---

## 2. Selecting the Right API Layer

| Integration Goal | Recommended Symbols | Notes |
| :--- | :--- | :--- |
| **Protect service-to-service traffic** | `KeyAuthority`, `NodeGateway`, `PeerInfo`, `generate_identity_keypair` | Use `NodeGateway` rather than raw `crypto_engine` calls when you need automatic anti-replay windows, revocation checks, chunk splitting/reassembly, and ledger emission. |
| **Custom binary framing or standalone cryptography** | `perform_handshake_initiator`, `perform_handshake_responder`, `encrypt_chunk`, `decrypt_chunk`, `sign_data`, `verify_signature`, `aes_gcm_*`, `derive_key` | Direct stateless primitives returning dataclasses/tuples without gateway session state. |
| **Crash-safe identity, key rotation & revocation** | `KeyAuthority` | Requires a 64-hex-character (256-bit) `master_kek_hex` generated at runtime (`secrets.token_hex(32)`) or loaded from a secrets manager. |
| **Injection-proof audit logging** | `AuditLedger` | Pass a dedicated `ML-DSA-65` signing key (`authority.get_or_create_ledger_signing_key()`) separated from authority control keys per NIST FIPS 204 Clause 8. |
| **Deterministic intrusion detection & containment** | `WatchdogDetector`, `LogEvent` | Wire `revocation_callback` directly to `authority.revoke_node(...)` and stream `AuditLedger` entries via `ledger.register_sink(...)`. |

---

## 3. Protocol Context Strings (FIPS 204 Domain Separation)

Every `ML-DSA-65` signature uses a distinct NIST FIPS 204 domain-separation `context` byte string (`|ctx| <= 255` bytes) so signatures generated in one protocol sub-flow never validate in another:

| Constant | Byte Value | Scope |
| :--- | :--- | :--- |
| `CTX_HANDSHAKE` | `b"qvault-handshake-v1"` | Hybrid handshake transcript authentication |
| `CTX_EPOCH` | `b"qvault-epoch-v1"` | Key-rotation epoch announcements |
| `CTX_REVOKE` | `b"qvault-revoke-v1"` | Cross-node revocation notices |
| `CTX_BACKUP` | `b"qvault-backup-v1"` | Authority `.qvbak` backups and low-level `crypto_engine` tickets |
| `CTX_LOG` | `b"qvault-log-v1"` | `AuditLedger` checkpoint signatures |
| `CTX_RESUMPTION` | `b"qvault-resumption-v1"` | `NodeGateway` single-use session resumption tickets |

---

## 4. End-to-End Closed-Loop SDK Quickstart

The example below provisions an authority, two service gateways, a tamper-evident ledger, and a watchdog detector wired together in one closed loop:

```python
import os
import secrets
import tempfile
import time
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
    authority = KeyAuthority(
        db_path=os.path.join(workdir, "authority.db"),
        master_kek_hex=secrets.token_hex(32),
        grace_period_seconds=30.0,
    )

    kp_portal = generate_identity_keypair("WebPortal")
    kp_auth = generate_identity_keypair("Auth")
    pub_portal = serialize_public_keys(kp_portal)
    pub_auth = serialize_public_keys(kp_auth)

    authority.register_node("WebPortal", pub_portal["signing_public"], pub_portal["kem_public"], pub_portal["x25519_public"])
    authority.register_node("Auth", pub_auth["signing_public"], pub_auth["kem_public"], pub_auth["x25519_public"])

    ledger_key = authority.get_or_create_ledger_signing_key()
    ledger = AuditLedger(
        ledger_path=os.path.join(workdir, "audit.jsonl"),
        signing_key=ledger_key,
        verify_key=ledger_key.public_key(),
        checkpoint_interval=50,
    )

    gw_portal = NodeGateway("WebPortal", serialize_private_keys(kp_portal), authority_client=authority, ledger=ledger)
    gw_auth = NodeGateway("Auth", serialize_private_keys(kp_auth), authority_client=authority, ledger=ledger)
    gw_portal.register_peer(PeerInfo("Auth", pub_auth["signing_public"], pub_auth["kem_public"], pub_auth["x25519_public"]))
    gw_auth.register_peer(PeerInfo("WebPortal", pub_portal["signing_public"], pub_portal["kem_public"], pub_portal["x25519_public"]))

    auth_pub = authority.get_authority_public_key_bytes()
    authority.register_revocation_callback(
        lambda notice: [g.apply_revocation(notice, auth_pub) for g in (gw_portal, gw_auth)]
    )
    detector = WatchdogDetector(
        allowed_paths=[["WebPortal", "Auth"]],
        clock_tolerance=5.0,
        revocation_callback=lambda actor: authority.revoke_node(actor, reason="watchdog-containment"),
    )

    kem_ct, eph_pub, sig, sid_a = gw_portal.initiate_handshake("Auth", epoch=authority.current_epoch)
    sid_b = gw_auth.complete_handshake("WebPortal", kem_ct, eph_pub, sig, epoch=authority.current_epoch)

    tx = gw_portal.send_message(sid_a, b"Authorized payload", "Auth")
    chunk = tx.encrypted_chunks[0]
    assert gw_auth.receive_chunk(sid_b, chunk["nonce"], chunk["ciphertext"], chunk["aad"], chunk["seq_num"]) == b"Authorized payload"

    now = time.time()
    for i, (src, dst) in enumerate([("WebPortal", "Auth"), ("Auth", "VaultDB"), ("VaultDB", "PayrollDB")]):
        detector.ingest_event(LogEvent(f"ev-{i}", now + i, now, "WebPortal", "SERVICE_CALL", src, dst, authority.current_epoch))
    detector.flush()
    alerts = detector.get_alerts()
    assert len(alerts) >= 1 and authority.is_revoked("WebPortal") is True
    assert ledger.verify_chain()["ok"] is True
    authority.close()
```
