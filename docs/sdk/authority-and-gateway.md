# Key Authority & Node Gateway API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. `KeyAuthority` — Control Plane, Rotation & Revocation

`KeyAuthority` manages node identity registration, epoch rotation with configurable grace windows, signed cross-node revocation broadcasts, acknowledgment latency tracking, encrypted backups (`.qvbak`), and crash-safe SQLite Write-Ahead Log (WAL) persistence (`BEGIN IMMEDIATE ... COMMIT` with `PRAGMA foreign_keys=ON`).

### Constructor & Properties

```python
from src.sdk import KeyAuthority

authority = KeyAuthority(
    db_path: str,
    master_kek_hex: str,
    grace_period_seconds: float = 30.0,
)
```

* **`db_path` (`str`):** SQLite WAL file path (parent directories created automatically).
* **`master_kek_hex` (`str`):** Required **64-hex-character** string (`32` bytes for `AES-256-GCM`) used to encrypt stored `ML-DSA-65` private signing seeds in SQLite and `.qvbak` archives. Generate at runtime with `secrets.token_hex(32)` or inject from a secrets manager. Raises `ValueError` if decoded length != 32 bytes, or if opening an existing database sealed under a different KEK.
* **`grace_period_seconds` (`float`, default `30.0`):** Window after `rotate_keys()` during which `current_epoch - 1` remains valid.
* **Properties:** `authority.current_epoch -> int`, `authority.revocation_epoch -> int` (both persist across crashes/restarts).

### Dataclasses

* **`NodeRecord`:** `node_id: str`, `signing_public_bytes: bytes`, `kem_public_bytes: bytes`, `x25519_public_bytes: bytes`, `key_epoch: int`, `registered_at: float`, `is_revoked: bool = False`, `revoked_at: Optional[float] = None`.
* **`RotationEpoch`:** `epoch: int`, `valid_from: float`, `grace_until: float`, `cutoff: float`, `signature: bytes`.
* **`RevocationNotice`:** `node_id: str`, `revocation_epoch: int`, `revoked_at: float`, `reason: str`, `signature: bytes`, `propagation_times: Dict[str, float]`.

### Method Reference

| Method & Signature | Parameters & Key Validation | Return Value | Exceptions & Notes |
| :--- | :--- | :--- | :--- |
| `register_node(node_id, signing_public_bytes, kem_public_bytes, x25519_public_bytes)` | Unique `node_id`; exact raw lengths `1952`, `1184`, `32` bytes | `NodeRecord` | Raises `ValueError` on duplicate `node_id` or incorrect key byte length. |
| `re_enroll_node(new_node_id, signing_public_bytes, kem_public_bytes, x25519_public_bytes, previous_node_id)` | `new_node_id != previous_node_id`; `previous_node_id` must already be revoked | `NodeRecord` | Keeps `previous_node_id` revoked; raises `ValueError` if old node is still active or IDs match. |
| `rotate_keys(announce_callback=None)` | Optional `Callable[[RotationEpoch], None]` invoked outside lock | `RotationEpoch` | Increments epoch atomically and signs announcement under `CTX_EPOCH`. |
| `is_epoch_valid(epoch, check_time=None)` | `epoch: int`; `check_time: Optional[float]` | `bool` | `True` for `current_epoch`, or `current_epoch - 1` if `t < grace_until`; `False` otherwise. |
| `revoke_node(node_id, reason="operator-triggered")` | Registered `node_id`; reason text | `RevocationNotice` | Signs notice under `CTX_REVOKE`, updates `is_revoked=1`, fires registered callbacks; raises `ValueError` if unregistered. |
| `is_revoked(node_id)` | `node_id: str` | `bool` | Queries SQLite `nodes` table (`False` if missing). |
| `record_revocation_ack(node_id, revocation_epoch, acked_at)` | Node ID, revocation epoch, ack Unix timestamp | `None` | Persisted into `ack_log` table for propagation latency measurement. |
| `get_propagation_stats(revocation_epoch)` | `revocation_epoch: int` | `dict` | Returns `{"revocation_epoch", "total_acked", "max_propagation_ms", "min_propagation_ms", "all_acks"}`. |
| `register_revocation_callback(callback)` | `Callable[[RevocationNotice], None]` | `None` | Executed sequentially outside authority lock on revocation. |
| `backup_keys(backup_path)` | Destination `.qvbak` path (`str`) | `dict` | Atomic `.tmp` write + replace; encrypted with KEK and signed with `CTX_BACKUP`; returns `{"path", "checksum", "size"}`. |
| `restore_from_backup(backup_path)` | Existing `.qvbak` file path (`str`) | `True` | Verifies `ML-DSA-65` signature **before** decryption and `SHA-256` checksum; raises `ValueError` on tampering/truncation/wrong KEK. |
| `get_node(node_id)` | `node_id: str` | `Optional[NodeRecord]` | Returns `None` if not registered. |
| `list_nodes(include_revoked=False)` | `include_revoked: bool` | `List[NodeRecord]` | Ordered by `registered_at`. |
| `list_revocations()` | — | `List[dict]` | List of `{"node_id", "revocation_epoch", "revoked_at", "reason"}`. |
| `get_or_create_ledger_signing_key()` | — | `MLDSA65PrivateKey` | Separate key persisted encrypted in `ledger_keys` across restarts (FIPS 204 Clause 8 separation). |
| `get_authority_public_key_bytes()` | — | `bytes` | DER SPKI (`1,974` bytes) for peers verifying `RevocationNotice` signatures. |
| `close()` | — | `None` | Runs `PRAGMA wal_checkpoint(FULL)` and closes SQLite handle. |

#### Example: Key Rotation Grace/Cutoff, Revocation Propagation, Re-Enrollment & Backups

```python
import secrets
import tempfile
from pathlib import Path
from src.sdk import KeyAuthority, NodeGateway, PeerInfo, generate_identity_keypair, serialize_private_keys, serialize_public_keys

with tempfile.TemporaryDirectory() as tmp:
    kek = secrets.token_hex(32)
    auth = KeyAuthority(f"{tmp}/auth.db", kek, grace_period_seconds=30.0)

    kp_a, kp_b = generate_identity_keypair("NodeA"), generate_identity_keypair("NodeB")
    pub_a, pub_b = serialize_public_keys(kp_a), serialize_public_keys(kp_b)
    auth.register_node("NodeA", pub_a["signing_public"], pub_a["kem_public"], pub_a["x25519_public"])
    auth.register_node("NodeB", pub_b["signing_public"], pub_b["kem_public"], pub_b["x25519_public"])

    gw_a = NodeGateway("NodeA", serialize_private_keys(kp_a), authority_client=auth)
    gw_b = NodeGateway("NodeB", serialize_private_keys(kp_b), authority_client=auth)
    gw_b.register_peer(PeerInfo("NodeA", pub_a["signing_public"], pub_a["kem_public"], pub_a["x25519_public"]))

    auth_pub = auth.get_authority_public_key_bytes()
    auth.register_revocation_callback(lambda n: [g.apply_revocation(n, auth_pub) for g in (gw_a, gw_b)])

    # 1. Epoch rotation & grace-window check
    rot = auth.rotate_keys()
    assert auth.is_epoch_valid(0, check_time=rot.valid_from + 10.0) is True
    assert auth.is_epoch_valid(0, check_time=rot.cutoff + 0.1) is False

    # 2. Cross-node revocation & propagation telemetry
    notice = auth.revoke_node("NodeA", reason="compromised-host")
    stats = auth.get_propagation_stats(notice.revocation_epoch)
    assert stats["total_acked"] == 2

    # 3. Replacement device enrollment while old key stays revoked
    kp_a2 = generate_identity_keypair("NodeA_v2")
    pub_a2 = serialize_public_keys(kp_a2)
    rec = auth.re_enroll_node("NodeA_v2", pub_a2["signing_public"], pub_a2["kem_public"], pub_a2["x25519_public"], previous_node_id="NodeA")
    assert rec.is_revoked is False and auth.is_revoked("NodeA") is True

    # 4. Signed + encrypted .qvbak backup & restore
    bak_info = auth.backup_keys(str(Path(tmp) / "authority.qvbak"))
    assert auth.restore_from_backup(bak_info["path"]) is True
    auth.close()
```

---

## 2. `NodeGateway` & Transport Protection

`NodeGateway` protects service endpoints with stateful forward-secret sessions, 64 KiB chunking (`MAX_CHUNK_SIZE = 65536`), out-of-order reassembly (`MAX_REASSEMBLY_TIMEOUT = 30.0`), a 1,024-bit per-session `AntiReplayWindow`, and single-use peer-bound resumption tickets (`SESSION_RESUMPTION_TTL = 3600`).

### Supporting Types

* **`PeerInfo(node_id: str, signing_public_bytes: bytes, kem_public_bytes: bytes, x25519_public_bytes: bytes)`**
* **`AntiReplayWindow(window_size: int = 1024)`:**
  * `is_acceptable(seq_num: int) -> bool`: Side-effect-free window check (`seq_num >= base_seq` and unseen bit).
  * `record(seq_num: int) -> None`: Shifts bitmask when `seq_num >= base_seq + window_size` and marks bit seen.
  * `check_and_record(seq_num: int) -> bool`: Atomically checks and records; returns `False` for duplicates or stale sequences.
* **`ActiveSession`:** Stores `session_id: bytes`, `peer_node_id: str`, `aes_key: bytes`, `epoch: int`, `created_at: float`, `last_used: float`, `next_send_seq: int`, `anti_replay: AntiReplayWindow`, and `in_flight: Dict[str, dict]`.
* **`TransferResult`:** `msg_id: str`, `success: bool`, `chunks_sent: int`, `chunks_received: int`, `delivery_ms: float`, `error: Optional[str]`, plus `encrypted_chunks: list[dict]` (`{"nonce", "ciphertext", "aad", "seq_num"}`) attached on successful `send_message()`.

### Constructor & Method Reference

```python
from src.sdk import NodeGateway

gw = NodeGateway(
    node_id: str,
    keypair_private_key_bytes: dict,  # Output of serialize_private_keys(kp)
    authority_client=None,            # Optional KeyAuthority instance
    ledger=None,                      # Optional AuditLedger instance
    policy=None,                      # Optional policy dict
)
```

| Method & Signature | Parameters | Return Value | Security & Rejection Behavior |
| :--- | :--- | :--- | :--- |
| `register_peer(peer: PeerInfo)` | Remote `PeerInfo` | `None` | Stores peer's raw keys for handshake verification. |
| `apply_revocation(notice, authority_public_key_bytes)` | `RevocationNotice`, Authority DER/raw pubkey | `bool` | Verifies `CTX_REVOKE` signature; drops active sessions with `notice.node_id`, logs `REVOCATION_ENFORCED`, records ack. |
| `initiate_handshake(peer_node_id, epoch)` | Peer ID, active `epoch` | `(kem_ct, eph_pub, sig, session_id)` | Raises `PermissionError` if self/peer revoked; `ValueError` on invalid epoch or unknown peer. Derives 32B `session_id`. |
| `complete_handshake(peer_node_id, kem_ciphertext, ephemeral_x25519_public_bytes, peer_signature, epoch)` | Peer handshake fields | `session_id: bytes` (32 bytes) | Raises `PermissionError` if revoked; `ValueError` on invalid epoch or `ML-DSA-65` signature mismatch (`HANDSHAKE_SIG_FAIL`). |
| `send_message(session_id, plaintext, recipient_node_id)` | Active 32B `session_id`, `bytes`, peer ID | `TransferResult` | Splits payload into 64 KiB chunks, allocates `next_send_seq` per chunk, binds `{"sender", "recipient", "epoch", "msg_id", "chunk_idx", "total_chunks", "seq"}` into AAD. |
| `receive_chunk(session_id, nonce, ciphertext, aad_json, seq_num)` | Chunk fields & sequence integer | Complete `bytes` on final chunk, else `None` | Validates session, revocation, epoch, `anti_replay.is_acceptable(seq_num)`, canonical AAD match, and GCM tag **before** advancing replay bitmask. Logs `REPLAY_DETECTED` or `RECEIVE_TAMPER_DETECTED` on failures. |
| `create_resumption_ticket(session_id, signing_key_bytes=None, master_kek=None)` | Active `session_id`; optional external signing DER / 32B KEK | Signed + encrypted ticket `bytes` | Raises `ValueError` on unknown `session_id`; embeds unique single-use `jti`, `peer_id`, `epoch`, and `expiry` (`+3,600s`) under `CTX_RESUMPTION`. |
| `resume_session(ticket_bytes, claiming_peer_id, verify_key_bytes=None, master_kek=None)` | Ticket `bytes`, peer identity claim | Rotated 32B `session_id` or `None` | Verifies `CTX_RESUMPTION` signature before decryption; blocks revoked peers, expired tickets, peer mismatches (`RESUMPTION_HIJACK_REJECTED`), expired epochs, and consumed `jti` replays (`RESUMPTION_REPLAY_REJECTED`). |
| `cleanup_stale_sessions(reassembly_timeout_seconds=30.0, session_ttl_seconds=3600)` | Idle timeout values (seconds) | `int` count purged | Evicts expired sessions (`SESSION_EXPIRED`) and incomplete chunk buffers (`REASSEMBLY_TIMEOUT`). |

#### Example: Out-of-Order Chunk Delivery & Peer-Bound Resumption

```python
import os
from src.sdk import NodeGateway, PeerInfo, generate_identity_keypair, serialize_private_keys, serialize_public_keys

kp_a, kp_b = generate_identity_keypair("GatewayA"), generate_identity_keypair("GatewayB")
pub_a, pub_b = serialize_public_keys(kp_a), serialize_public_keys(kp_b)
gw_a = NodeGateway("GatewayA", serialize_private_keys(kp_a))
gw_b = NodeGateway("GatewayB", serialize_private_keys(kp_b))
gw_a.register_peer(PeerInfo("GatewayB", pub_b["signing_public"], pub_b["kem_public"], pub_b["x25519_public"]))
gw_b.register_peer(PeerInfo("GatewayA", pub_a["signing_public"], pub_a["kem_public"], pub_a["x25519_public"]))

ct, eph, sig, sid_a = gw_a.initiate_handshake("GatewayB", epoch=0)
sid_b = gw_b.complete_handshake("GatewayA", ct, eph, sig, epoch=0)

# Send 65 KiB payload (2 chunks) and deliver chunk 1 before chunk 0
payload = os.urandom(65536 + 256)
chunks = gw_a.send_message(sid_a, payload, "GatewayB").encrypted_chunks
assert gw_b.receive_chunk(sid_b, chunks[1]["nonce"], chunks[1]["ciphertext"], chunks[1]["aad"], chunks[1]["seq_num"]) is None
assert gw_b.receive_chunk(sid_b, chunks[0]["nonce"], chunks[0]["ciphertext"], chunks[0]["aad"], chunks[0]["seq_num"]) == payload

# Peer-bound, single-use session resumption
ticket = gw_b.create_resumption_ticket(sid_b)
assert gw_b.resume_session(ticket, "ImpersonatorNode") is None
rotated_sid = gw_b.resume_session(ticket, "GatewayA")
assert rotated_sid is not None and rotated_sid != sid_b
assert gw_b.resume_session(ticket, "GatewayA") is None  # Single-use JTI replay blocked
```
