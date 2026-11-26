# Cryptographic Engine API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. Constants & Imports

```python
from src.sdk import (
    CTX_BACKUP,
    CTX_EPOCH,
    CTX_HANDSHAKE,
    CTX_LOG,
    CTX_RESUMPTION,
    CTX_REVOKE,
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

## 2. Dataclasses

### `HybridKeyPair`

Container holding segregated post-quantum signature, post-quantum KEM, and classical Diffie-Hellman keys.

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `signing_private` | `MLDSA65PrivateKey` | Required | Long-term FIPS 204 signing key (never used for encryption). |
| `signing_public` | `MLDSA65PublicKey` | Required | Corresponding verification public key (`1,952` bytes raw). |
| `kem_private` | `MLKEM768PrivateKey` | Required | FIPS 203 decapsulation key (`64` bytes raw seed / DER PKCS8). |
| `kem_public` | `MLKEM768PublicKey` | Required | Corresponding encapsulation public key (`1,184` bytes raw). |
| `x25519_private` | `X25519PrivateKey` | Required | Classical Diffie-Hellman key (`32` bytes raw). |
| `node_id` | `str` | `""` | Logical service-node identifier. |

### `SessionKeys`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `session_id` | `bytes` | Required | `16`-byte derived session identifier. |
| `aes_key` | `bytes` | Required | `32`-byte `AES-256-GCM` symmetric key. |
| `peer_id` | `str` | Required | Authenticated remote node identifier. |
| `epoch` | `int` | Required | Protocol epoch active at derivation. |
| `created_at` | `float` | `time.time()` | Unix timestamp when derived. |

### `EncryptedChunk`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `msg_id` | `str` | Required | Message identifier shared across chunks. |
| `chunk_idx` | `int` | Required | Zero-based chunk index. |
| `total_chunks` | `int` | Required | Total chunk count for the message. |
| `sender_id` | `str` | Required | Originating node ID bound in AAD. |
| `recipient_id` | `str` | Required | Intended recipient node ID bound in AAD. |
| `key_epoch` | `int` | Required | Epoch bound in AAD. |
| `seq_num` | `int` | Required | Sequence number bound in AAD. |
| `nonce` | `bytes` | Required | `12`-byte random GCM nonce. |
| `ciphertext` | `bytes` | Required | Encrypted payload with appended `16`-byte GCM tag. |
| `tag_included` | `bool` | `True` | Always `True`; tag is appended to `ciphertext`. |

### `HandshakeResult`

| Field | Type | Description |
| :--- | :--- | :--- |
| `session_keys` | `SessionKeys` | Derived session key container. |
| `transcript_hash` | `bytes` | `32`-byte `SHA-256` digest of canonical handshake transcript. |
| `peer_node_id` | `str` | Authenticated remote peer identifier. |

---

## 3. Key Generation, Serialization & Loading

### `generate_identity_keypair(node_id: str) -> HybridKeyPair`

* **Parameters:** `node_id` (`str`) — unique service-node identity.
* **Returns:** Freshly generated `HybridKeyPair` using CSPRNG key generation.

### `serialize_public_keys(keypair: HybridKeyPair) -> dict[str, bytes]`

* **Parameters:** `keypair` (`HybridKeyPair`).
* **Returns:** `dict` with exact raw byte representations:
  * `"signing_public"`: `bytes` (`1,952` bytes)
  * `"kem_public"`: `bytes` (`1,184` bytes)
  * `"x25519_public"`: `bytes` (`32` bytes)

### `serialize_private_keys(keypair: HybridKeyPair) -> dict[str, bytes]`

* **Parameters:** `keypair` (`HybridKeyPair`).
* **Returns:** `dict` formatted for `NodeGateway` initialization:
  * `"mldsa_private"`: PKCS8 DER `bytes` (`54` bytes)
  * `"mlkem_private"`: PKCS8 DER `bytes` (`86` bytes)
  * `"x25519_private"`: Raw `bytes` (`32` bytes)

### `load_mldsa_public_key(data: bytes) -> MLDSA65PublicKey`

* **Parameters:** `data` (`bytes`) — either `1,952`-byte raw key or DER SPKI (`1,974` bytes).
* **Returns:** `MLDSA65PublicKey`.
* **Raises:** `ValueError` if parsed key is not an `ML-DSA-65` public key.

### `load_mlkem_public_key(data: bytes) -> MLKEM768PublicKey`

* **Parameters:** `data` (`bytes`) — either `1,184`-byte raw key or DER SPKI (`1,206` bytes).
* **Returns:** `MLKEM768PublicKey`.
* **Raises:** `ValueError` if parsed key is not an `ML-KEM-768` public key.

---

## 4. Hybrid Handshake & Chunk Encryption

### `perform_handshake_initiator(my_keypair, peer_kem_public, peer_signing_public, peer_x25519_public_bytes, peer_node_id, epoch) -> tuple[HandshakeResult, bytes, bytes, bytes]`

* **Parameters:**
  * `my_keypair` (`HybridKeyPair`): Initiator identity keys.
  * `peer_kem_public` (`MLKEM768PublicKey`): Responder's public encapsulation key.
  * `peer_signing_public` (`MLDSA65PublicKey`): Responder's verification key.
  * `peer_x25519_public_bytes` (`bytes`): Responder's `32`-byte raw X25519 public key.
  * `peer_node_id` (`str`): Responder identifier.
  * `epoch` (`int`): Active rotation epoch.
* **Returns:** 4-tuple `(handshake_result, kem_ciphertext, ephemeral_x25519_public_bytes, transcript_signature)`.
  * `kem_ciphertext`: `1,088` bytes (`ML-KEM-768` ciphertext).
  * `ephemeral_x25519_public_bytes`: `32` bytes.
  * `transcript_signature`: `ML-DSA-65` signature (`CTX_HANDSHAKE`).

### `perform_handshake_responder(my_keypair, kem_ciphertext, peer_x25519_ephemeral_bytes, peer_signing_public, peer_node_id, peer_signature, epoch) -> HandshakeResult`

* **Parameters:** Responder identity keypair, initiator handshake parameters (`kem_ciphertext`, `peer_x25519_ephemeral_bytes`, `peer_signing_public`, `peer_node_id`, `peer_signature`, `epoch`).
* **Returns:** `HandshakeResult` matching the initiator's `session_keys`.
* **Raises:** `ValueError` if `ML-DSA-65` verification under `CTX_HANDSHAKE` fails.

### `encrypt_chunk(session_keys, plaintext, msg_id, chunk_idx, total_chunks, seq_num, sender_id, recipient_id) -> EncryptedChunk`

* **Parameters:** Active `SessionKeys`, chunk `plaintext` (`bytes`), `msg_id` (`str`), `chunk_idx` (`int`), `total_chunks` (`int`), `seq_num` (`int`), `sender_id` (`str`), `recipient_id` (`str`).
* **Returns:** `EncryptedChunk` with fresh `12`-byte random nonce and canonical JSON AAD binding all metadata fields.

### `decrypt_chunk(session_keys, chunk, sender_id, recipient_id) -> bytes`

* **Parameters:** `SessionKeys`, `EncryptedChunk`, expected `sender_id` (`str`), expected `recipient_id` (`str`).
* **Returns:** Decrypted plaintext `bytes`.
* **Raises:** `cryptography.exceptions.InvalidTag` on ciphertext tampering or any AAD metadata mismatch (including recipient substitution).

---

## 5. Signatures, Symmetric Primitives & Resumption Tickets

| Function | Parameters & Defaults | Return Value | Failure Behavior |
| :--- | :--- | :--- | :--- |
| `sign_data` | `(private_key: MLDSA65PrivateKey, data: bytes, ctx: bytes)` | Raw `ML-DSA-65` signature (`bytes`) | Raises on invalid inputs |
| `verify_signature` | `(public_key: MLDSA65PublicKey, data: bytes, signature: bytes, ctx: bytes)` | `bool` (`True` if valid under `ctx`) | Returns `False` on `InvalidSignature` |
| `aes_gcm_encrypt` | `(key: bytes, plaintext: bytes, aad: bytes = b"")` | `tuple[bytes, bytes]` (`(nonce, ciphertext_with_tag)`) | Raises on invalid key length |
| `aes_gcm_decrypt` | `(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"")` | Plaintext `bytes` | Raises `InvalidTag` |
| `derive_key` | `(secret: bytes, info: bytes, length: int = 32)` | Derived key `bytes` (`length` bytes via `HKDF-SHA256`) | Raises on invalid length |
| `sha256_hash` | `(data: bytes)` | `32`-byte raw `SHA-256` digest | — |
| `generate_session_resumption_ticket` | `(session_keys: SessionKeys, signing_key: MLDSA65PrivateKey, master_kek: bytes)` | Serialized encrypted & signed ticket `bytes` (`1h` TTL) | Raises on encryption/signing error |
| `validate_resumption_ticket` | `(ticket_bytes: bytes, verify_key: MLDSA65PublicKey, master_kek: bytes, claiming_peer_id: str)` | `Optional[dict]` (`session_id`, `peer_id`, `epoch`, `expiry`) | Returns `None` on bad signature, bad tag, expiry, or peer mismatch |
