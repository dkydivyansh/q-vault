# Cryptographic Engine API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. Key Types, Formats & FIPS Parameter Sizes

Q-Vault Sentinel enforces strict key-usage separation pursuant to **NIST FIPS 204 Clause 8**: `ML-DSA-65` identity keys handle authentication and audit non-repudiation only, while `ML-KEM-768` and `X25519` keys handle key establishment only.

| Key Role | Algorithm / Standard | Format in SDK | Byte Length | Usage |
| :--- | :--- | :--- | :---: | :--- |
| **Node Signing Public Key** | `ML-DSA-65` (FIPS 204) | Raw public bytes / DER SPKI | `1,952` (raw) / `1,974` (DER) | Authenticates handshakes, epoch rotations, revocations, backups, and ledger checkpoints. |
| **Node Signing Private Key** | `ML-DSA-65` (FIPS 204) | `MLDSA65PrivateKey` or PKCS8 DER | `54` (PKCS8 seed DER) | Generates hedged `ML-DSA-65` signatures (`3,309` bytes). Never used for encryption. |
| **Node KEM Public Key** | `ML-KEM-768` (FIPS 203) | Raw public bytes / DER SPKI | `1,184` (raw) / `1,206` (DER) | Encapsulates a `32`-byte shared secret into a `1,088`-byte ciphertext. |
| **Node KEM Private Key** | `ML-KEM-768` (FIPS 203) | `MLKEM768PrivateKey` or PKCS8 DER | `86` (PKCS8 seed DER) | Decapsulates incoming `ML-KEM-768` ciphertexts. |
| **Classical DH Identity / Ephemeral Key** | `X25519` | Raw public / private bytes | `32` | Hybrid ECDH contribution combined with `ML-KEM-768` shared secret; ephemeral keys are wiped immediately after derivation. |
| **Symmetric Session Key** | `AES-256-GCM` | Raw `bytes` (`HKDF-SHA256`) | `32` | Encrypts chunked payloads with `12`-byte random nonces and `16`-byte appended GCM authentication tags. |
| **Master Key-Encryption Key (KEK)** | `AES-256-GCM` | `64`-char hex string (`32` bytes) | `32` | Seals authority keys in SQLite WAL, `.qvbak` archives, and resumption tickets. Generated at runtime via `secrets.token_hex(32)`. |

---

## 2. Imports & Context Constants

```python
from src.sdk import (
    CTX_BACKUP,     # b"qvault-backup-v1"
    CTX_EPOCH,      # b"qvault-epoch-v1"
    CTX_HANDSHAKE,  # b"qvault-handshake-v1"
    CTX_LOG,        # b"qvault-log-v1"
    CTX_RESUMPTION, # b"qvault-resumption-v1"
    CTX_REVOKE,     # b"qvault-revoke-v1"
    EncryptedChunk,
    HandshakeResult,
    HybridKeyPair,
    SessionKeys,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    decrypt_chunk,
    derive_key,
    encrypt_chunk,
    generate_identity_keypair,
    generate_session_resumption_ticket,
    load_mldsa_public_key,
    load_mlkem_public_key,
    perform_handshake_initiator,
    perform_handshake_responder,
    serialize_private_keys,
    serialize_public_keys,
    sha256_hash,
    sign_data,
    validate_resumption_ticket,
    verify_signature,
)
```

---

## 3. Dataclasses

### `HybridKeyPair`
Holds segregated `ML-DSA-65`, `ML-KEM-768`, and `X25519` key material for a single logical identity.
* `signing_private` (`MLDSA65PrivateKey`) — Long-term signing key.
* `signing_public` (`MLDSA65PublicKey`) — Verification key.
* `kem_private` (`MLKEM768PrivateKey`) — Post-quantum decapsulation key.
* `kem_public` (`MLKEM768PublicKey`) — Post-quantum encapsulation key.
* `x25519_private` (`X25519PrivateKey`) — Classical Diffie-Hellman key.
* `node_id` (`str`, default `""`) — Logical identity bound into handshake transcripts.

### `SessionKeys`
Derived symmetric state shared between initiator and responder.
* `session_id` (`bytes`) — `16`-byte derived session identifier (`SHA-256(aes_key || responder_id)[:16]`). *(Note: `NodeGateway` derives a full `32`-byte session ID binding the transcript hash.)*
* `aes_key` (`bytes`) — `32`-byte `AES-256-GCM` key derived via `HKDF-SHA256(info=b"qvault-session-v1")`.
* `peer_id` (`str`) — Authenticated peer node identifier.
* `epoch` (`int`) — Protocol epoch active when keys were established.
* `created_at` (`float`, default `time.time()`) — Unix timestamp at derivation.

### `EncryptedChunk`
* `msg_id` (`str`), `chunk_idx` (`int`), `total_chunks` (`int`), `sender_id` (`str`), `recipient_id` (`str`), `key_epoch` (`int`), `seq_num` (`int`), `nonce` (`bytes`, 12 bytes), `ciphertext` (`bytes`, plaintext + 16-byte tag), `tag_included` (`bool`, default `True`).

### `HandshakeResult`
* `session_keys` (`SessionKeys`), `transcript_hash` (`bytes`, 32-byte `SHA-256`), `peer_node_id` (`str`).

---

## 4. Identity Key Management Functions

### `generate_identity_keypair(node_id: str) -> HybridKeyPair`
Generates fresh CSPRNG `ML-DSA-65`, `ML-KEM-768`, and `X25519` keys bound to `node_id`.
* **Parameters:** `node_id: str` — unique non-empty service identifier.
* **Returns:** `HybridKeyPair`.

### `serialize_public_keys(keypair: HybridKeyPair) -> dict[str, bytes]`
Exports public keys to exact FIPS 203/204 and X25519 raw byte strings suitable for `KeyAuthority.register_node()` and `PeerInfo`.
* **Returns:** `{"signing_public": bytes(1952), "kem_public": bytes(1184), "x25519_public": bytes(32)}`.

### `serialize_private_keys(keypair: HybridKeyPair) -> dict[str, bytes]`
Exports private keys formatted for `NodeGateway` construction.
* **Returns:** `{"mldsa_private": bytes(54 PKCS8 DER), "mlkem_private": bytes(86 PKCS8 DER), "x25519_private": bytes(32 Raw)}`.

### `load_mldsa_public_key(data: bytes) -> MLDSA65PublicKey`
Loads an `ML-DSA-65` public key from raw bytes (`1,952` bytes) or DER SPKI (`1,974` bytes). Raises `ValueError` for other key types or invalid bytes.

### `load_mlkem_public_key(data: bytes) -> MLKEM768PublicKey`
Loads an `ML-KEM-768` public key from raw bytes (`1,184` bytes) or DER SPKI (`1,206` bytes). Raises `ValueError` for other key types or invalid bytes.

#### Example: Generating, Serializing & Reloading Identity Keys

```python
from src.sdk import (
    generate_identity_keypair,
    load_mldsa_public_key,
    load_mlkem_public_key,
    serialize_private_keys,
    serialize_public_keys,
)

kp = generate_identity_keypair("BillingService")
pub_bytes = serialize_public_keys(kp)    # 1952B ML-DSA-65, 1184B ML-KEM-768, 32B X25519
priv_bytes = serialize_private_keys(kp)  # 54B DER, 86B DER, 32B raw

dsa_pub = load_mldsa_public_key(pub_bytes["signing_public"])
kem_pub = load_mlkem_public_key(pub_bytes["kem_public"])
```

---

## 5. Hybrid Forward-Secret Handshake & Chunk Encryption

### `perform_handshake_initiator(my_keypair, peer_kem_public, peer_signing_public, peer_x25519_public_bytes, peer_node_id, epoch) -> tuple[HandshakeResult, bytes, bytes, bytes]`
Generates a single-use ephemeral `X25519` keypair, performs ECDH + `ML-KEM-768` encapsulation, derives `AES-256-GCM` `SessionKeys` via `HKDF-SHA256`, clears the ephemeral private key reference, and signs the canonical handshake transcript under `CTX_HANDSHAKE`.
* **Parameters:**
  * `my_keypair` (`HybridKeyPair`) — Initiator's identity keypair.
  * `peer_kem_public` (`MLKEM768PublicKey`) — Responder's encapsulation public key.
  * `peer_signing_public` (`MLDSA65PublicKey`) — Responder's verification public key.
  * `peer_x25519_public_bytes` (`bytes`) — Responder's 32-byte raw X25519 public key.
  * `peer_node_id` (`str`) — Expected responder identifier.
  * `epoch` (`int`) — Active key epoch integer.
* **Returns:** `(handshake_result, kem_ciphertext, ephemeral_x25519_public_bytes, transcript_signature)`.

### `perform_handshake_responder(my_keypair, kem_ciphertext, peer_x25519_ephemeral_bytes, peer_signing_public, peer_node_id, peer_signature, epoch) -> HandshakeResult`
Decapsulates `kem_ciphertext`, completes ephemeral `X25519` exchange, derives `SessionKeys`, and verifies `peer_signature` under `CTX_HANDSHAKE` before returning keys.
* **Raises:** `ValueError` if `ML-DSA-65` transcript verification fails.

### `encrypt_chunk(session_keys, plaintext, msg_id, chunk_idx, total_chunks, seq_num, sender_id, recipient_id) -> EncryptedChunk`
Encrypts `plaintext` with a fresh 12-byte random nonce and binds canonical JSON `{"chunk_idx", "key_epoch", "msg_id", "recipient_id", "sender_id", "seq_num", "total_chunks"}` as `AES-256-GCM` Associated Data (AAD).

### `decrypt_chunk(session_keys, chunk, sender_id, recipient_id) -> bytes`
Reconstructs canonical JSON AAD using expected `sender_id`, `recipient_id`, and `session_keys.epoch` and decrypts `chunk`.
* **Raises:** `cryptography.exceptions.InvalidTag` on ciphertext tampering, wrong key/epoch, or sender/recipient substitution.

#### Example: Hybrid Handshake & Recipient-Binding Verification

```python
from cryptography.exceptions import InvalidTag
from src.sdk import (
    decrypt_chunk,
    encrypt_chunk,
    generate_identity_keypair,
    perform_handshake_initiator,
    perform_handshake_responder,
    serialize_public_keys,
)

alice = generate_identity_keypair("ServiceA")
bob = generate_identity_keypair("ServiceB")
bob_x25519 = serialize_public_keys(bob)["x25519_public"]

hs_a, kem_ct, eph_pub, sig = perform_handshake_initiator(
    alice, bob.kem_public, bob.signing_public, bob_x25519, "ServiceB", epoch=1
)
hs_b = perform_handshake_responder(
    bob, kem_ct, eph_pub, alice.signing_public, "ServiceA", sig, epoch=1
)

chunk = encrypt_chunk(hs_a.session_keys, b"Payroll delta", "msg-10", 0, 1, seq_num=1, sender_id="ServiceA", recipient_id="ServiceB")
assert decrypt_chunk(hs_b.session_keys, chunk, sender_id="ServiceA", recipient_id="ServiceB") == b"Payroll delta"

try:
    decrypt_chunk(hs_b.session_keys, chunk, sender_id="ServiceA", recipient_id="WrongService")
except InvalidTag:
    pass  # Recipient substitution fails GCM tag authentication.
```

---

## 6. Signatures, Symmetric AEAD, Key Derivation & Tickets

### `sign_data(private_key: MLDSA65PrivateKey, data: bytes, ctx: bytes) -> bytes`
Signs `data` using FIPS 204 hedged `ML-DSA-65` bound to domain-separation context `ctx` (`|ctx| <= 255`).

### `verify_signature(public_key: MLDSA65PublicKey, data: bytes, signature: bytes, ctx: bytes) -> bool`
Verifies `signature` over `data` under exact `ctx`. Returns `True` when valid; catches `InvalidSignature` and returns `False` on tampering or cross-context replay.

### `aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]`
Encrypts arbitrary bytes using a 32-byte `key` (`AES-256-GCM`) and fresh 12-byte random nonce, returning `(nonce, ciphertext_with_tag)`.

### `aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes`
Verifies tag against `aad` and decrypts `ciphertext`; raises `cryptography.exceptions.InvalidTag` on mismatch.

### `derive_key(secret: bytes, info: bytes, length: int = 32) -> bytes`
Derives a deterministic `length`-byte subkey from `secret` using `HKDF-SHA256` with domain tag `info`.

### `sha256_hash(data: bytes) -> bytes`
Returns the raw 32-byte `SHA-256` digest of `data`.

### `generate_session_resumption_ticket(session_keys: SessionKeys, signing_key: MLDSA65PrivateKey, master_kek: bytes) -> bytes`
Seals `{session_id, peer_id, epoch, expiry}` (`+3,600s` TTL) with `AES-256-GCM` under `master_kek` and signs the ciphertext under `CTX_BACKUP` (`b"qvault-backup-v1"`). *(Note: Prefer `NodeGateway.create_resumption_ticket()` when you need single-use `jti` replay tracking under `CTX_RESUMPTION`.)*

### `validate_resumption_ticket(ticket_bytes: bytes, verify_key: MLDSA65PublicKey, master_kek: bytes, claiming_peer_id: str) -> Optional[dict]`
Verifies `ML-DSA-65` signature **before** decrypting with `master_kek`, then checks ticket expiration (`expiry > now`) and `peer_id == claiming_peer_id`. Returns parsed ticket `dict` on success or `None` on any failure.

#### Example: Domain-Separated Signing, HKDF Subkeys & AEAD

```python
import secrets
from src.sdk import (
    CTX_EPOCH,
    CTX_REVOKE,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_key,
    generate_identity_keypair,
    sha256_hash,
    sign_data,
    verify_signature,
)

authority_kp = generate_identity_keypair("Authority")
msg = b"epoch=4"
sig = sign_data(authority_kp.signing_private, msg, CTX_EPOCH)

assert verify_signature(authority_kp.signing_public, msg, sig, CTX_EPOCH) is True
assert verify_signature(authority_kp.signing_public, msg, sig, CTX_REVOKE) is False

master = secrets.token_bytes(32)
subkey = derive_key(master, info=b"backup-wrapping-v1", length=32)
nonce, ct = aes_gcm_encrypt(subkey, b"sealed-record", aad=sha256_hash(msg))
assert aes_gcm_decrypt(subkey, nonce, ct, aad=sha256_hash(msg)) == b"sealed-record"
```
