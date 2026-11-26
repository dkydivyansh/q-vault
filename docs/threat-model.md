# Threat Model, Security Assumptions & Stated Limitations

> Return to [`docs/architecture.md`](architecture.md) for system architecture and security controls.

---

## 1. Adversary Capabilities Addressed

* **Passive & Harvest-Now-Decrypt-Later Eavesdropping:** Mitigated by hybrid ephemeral `X25519 + ML-KEM-768` forward-secret sessions and `AES-256-GCM` payload encryption.
* **Packet Replay, Tampering & Re-Routing:** Mitigated by per-session 1,024-slot sliding anti-replay bitmasks (mutated only after AEAD authentication succeeds), strict `sender`, `recipient`, `epoch`, and `seq` AAD equality verification, and single-use resumption ticket identifiers (`jti`).
* **Compromised Valid Credentials & Lateral Movement:** Mitigated by deterministic rule and directed service-graph containment triggering automated `ML-DSA-65`-signed revocation across all registered service gateways.
* **Log Forgery & Storage/Backup Tampering:** Mitigated by strict `ensure_ascii=True` JSONL escaping, `SHA-256` hash chaining with persisted `ML-DSA-65` checkpoints, SQLite WAL `BEGIN IMMEDIATE` transactions, and verify-before-decrypt encrypted backups.

---

## 2. Explicit Trust Assumptions & Known Limitations

1. **CPython Immutable Memory Semantics:** Although ephemeral private-key references (`ephemeral_x25519_private`) are cleared immediately after key agreement, CPython does not guarantee deterministic physical RAM scrubbing for immutable `bytes` objects or garbage-collected heap allocations; native FFI key buffers rely on `pyca/cryptography` / OpenSSL cleanup.
2. **Single-Host Control Plane HTTP Scope:** The FastAPI control plane (`src/app/`) is intended for localhost or isolated verification environments (`127.0.0.1`) without multi-tenant RBAC or built-in mTLS client authentication on administrative routes. Production multi-host deployment requires placing `/api/v1/*` behind authenticated mTLS or reverse-proxy authorization.
3. **Single-Authority Root & KEK Custody:** Security relies on uncompromised custody of `QVAULT_MASTER_KEK` and the Authority's `ML-DSA-65` private key; compromise of `QVAULT_MASTER_KEK` permits decryption of stored authority keys, ledger checkpoint keys, and encrypted backups.
4. **Clock-Skew vs. Time-to-Alert Trade-Off:** Enabling the $\pm 5\text{ s}$ `ClockSkewBuffer` introduces up to `5.0 s` of intentional hold latency on live streaming events so out-of-order logs sort deterministically before rule evaluation, and causal ordering of adjacent events within that window cannot be established (`ordering_uncertain: true`).
5. **In-Memory Session & Reassembly Buffers:** While revocations, epochs, node public identities, and ledger checkpoint keys persist across crashes in SQLite WAL, active ephemeral session keys and partial in-flight chunk buffers are intentionally non-persistent and require a fresh handshake or valid resumption ticket after process restart.
6. **Out-of-Band Initial Peer Key Distribution:** Initial node registration relies on trusted provisioning of node public keys into the Authority; transitive PKI certificate chains and external ACME/SPIFFE identity federation are outside the current scope.
