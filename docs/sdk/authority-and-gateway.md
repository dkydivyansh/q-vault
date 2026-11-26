# Key Authority & Node Gateway API Reference (`src.sdk`)

> Return to [`docs/sdk/overview.md`](overview.md).

---

## 1. `KeyAuthority`

SQLite WAL-mode control plane managing registered node identities, epoch rotations, cross-node revocations, propagation tracking, encrypted ledger key storage, and verified backups.

### Constructor

```python
KeyAuthority(
    db_path: str,
    master_kek_hex: str,
    grace_period_seconds: float = 30.0,
) -> None
```

| Parameter | Type | Default | Expected Input / Validation |
| :--- | :--- | :--- | :--- |
| `db_path` | `str` | Required | Filesystem path for the SQLite WAL store (parent directories auto-created). |
| `master_kek_hex` | `str` | Required | `64`-character hex string (`32` bytes for `AES-256-GCM`); raises `ValueError` otherwise. |
| `grace_period_seconds` | `float` | `30.0` | Window during which the previous epoch remains valid after a rotation. |

### Properties

* `current_epoch -> int`: Current monotonically increasing epoch counter reloaded from SQLite across restarts.
* `revocation_epoch -> int`: Current monotonically increasing revocation counter reloaded from SQLite across restarts.

### Dataclasses Returned

* **`NodeRecord`:** `node_id: str`, `signing_public_bytes: bytes`, `kem_public_bytes: bytes`, `x25519_public_bytes: bytes`, `key_epoch: int`, `registered_at: float`, `is_revoked: bool = False`, `revoked_at: Optional[float] = None`.
* **`RotationEpoch`:** `epoch: int`, `valid_from: float`, `grace_until: float`, `cutoff: float`, `signature: bytes`.
* **`RevocationNotice`:** `node_id: str`, `revocation_epoch: int`, `revoked_at: float`, `reason: str`, `signature: bytes`, `propagation_times: Dict[str, float]`.

### Methods

| Method & Signature | Expected Inputs | Return Value / Output | Exceptions / Persistence |
| :--- | :--- | :--- | :--- |
| `register_node(node_id, signing_public_bytes, kem_public_bytes, x25519_public_bytes)` | Unique `node_id`; exact raw lengths `1952`, `1184`, `32` bytes | `NodeRecord` | `ValueError` on bad key size or duplicate `node_id`; atomic WAL `BEGIN IMMEDIATE` commit |
| `re_enroll_node(new_node_id, signing_public_bytes, kem_public_bytes, x25519_public_bytes, previous_node_id)` | Different `new_node_id`; `previous_node_id` must already be revoked | `NodeRecord` | `ValueError` if `new_node_id == previous_node_id` or old node is not revoked |
| `rotate_keys(announce_callback=None)` | Optional callable `fn(RotationEpoch)` invoked outside lock | `RotationEpoch` (`signature` signed with `CTX_EPOCH`) | Persisted atomically in `epochs` table |
| `is_epoch_valid(epoch, check_time=None)` | Integer `epoch`; optional Unix timestamp `check_time` | `True` if `epoch == current_epoch` or `epoch == current_epoch - 1` and `check_time < grace_until`; `False` otherwise | Queries persisted `epochs` table |
| `revoke_node(node_id, reason='operator-triggered')` | Registered `node_id`; reason string | `RevocationNotice` signed under `CTX_REVOKE` | `ValueError` if unregistered; triggers callbacks outside lock; persists across restarts |
| `is_revoked(node_id)` | `node_id: str` | `bool` (`True` if revoked in DB; `False` if active or missing) | Read from SQLite `nodes` table |
| `record_revocation_ack(node_id, revocation_epoch, acked_at)` | Node ID, revocation epoch, Unix timestamp | `None` | Inserts row into `ack_log` table |
| `get_propagation_stats(revocation_epoch)` | `revocation_epoch: int` | `{"revocation_epoch": int, "total_acked": int, "max_propagation_ms": float, "min_propagation_ms": float, "all_acks": list}` | Computes latency from `revoked_at` to each `acked_at` |
| `register_revocation_callback(callback)` | `Callable[[RevocationNotice], None]` | `None` | Invoked FIFO on `revoke_node()` |
| `backup_keys(backup_path)` | Destination file path (`str`) | `{"path": str, "checksum": str, "size": int}` | Atomic `.tmp` write + replace; encrypted with KEK and signed with `CTX_BACKUP` |
| `restore_from_backup(backup_path)` | Existing backup file path (`str`) | `True` on success | Verifies signature before decryption and checksum; raises `ValueError` on any tamper/corruption |
| `get_node(node_id)` | `node_id: str` | `Optional[NodeRecord]` | Queries `nodes` table |
| `list_nodes(include_revoked=False)` | `include_revoked: bool` | `List[NodeRecord]` ordered by `registered_at` | Queries `nodes` table |
| `list_revocations()` | — | `List[dict]` (`node_id`, `revocation_epoch`, `revoked_at`, `reason`) | Queries `revocations` table |
| `get_or_create_ledger_signing_key()` | — | `MLDSA65PrivateKey` dedicated to audit ledger checkpoints | Encrypted in `ledger_keys` table across restarts |
| `get_authority_public_key_bytes()` | — | DER SPKI `bytes` of Authority's `ML-DSA-65` public key | — |
| `close()` | — | `None` | Runs `PRAGMA wal_checkpoint(FULL)` and closes connection |

---

## 2. `NodeGateway` & Supporting Classes

### Supporting Types

* **`PeerInfo(node_id: str, signing_public_bytes: bytes, kem_public_bytes: bytes, x25519_public_bytes: bytes)`**
* **`AntiReplayWindow(window_size: int = 1024)`:**
  * `is_acceptable(seq_num: int) -> bool`: Read-only window membership check without mutating bitmask state.
  * `record(seq_num: int) -> None`: Advances window if needed and marks `seq_num` seen.
  * `check_and_record(seq_num: int) -> bool`: Combined check-and-record helper.
* **`ActiveSession`:** Holds `session_id`, `peer_node_id`, `aes_key`, `epoch`, `created_at`, `last_used`, `next_send_seq`, per-session `anti_replay: AntiReplayWindow`, and `in_flight` reassembly map.
* **`TransferResult`:** Holds `msg_id: str`, `success: bool`, `chunks_sent: int`, `chunks_received: int`, `delivery_ms: float`, `error: Optional[str]`, plus `encrypted_chunks` list on outbound sends.

### `NodeGateway` Constructor

```python
NodeGateway(
    node_id: str,
    keypair_private_key_bytes: dict,
    authority_client=None,
    ledger=None,
    policy: dict = None,
)
```

| Parameter | Type | Default | Expected Input |
| :--- | :--- | :--- | :--- |
| `node_id` | `str` | Required | Local service node identifier. |
| `keypair_private_key_bytes` | `dict` | Required | Output from `serialize_private_keys()` (`mldsa_private`, `mlkem_private`, `x25519_private`). |
| `authority_client` | `Optional[KeyAuthority]` | `None` | Optional authority instance for live revocation and epoch checks. |
| `ledger` | `Optional[AuditLedger]` | `None` | Optional ledger instance recording gateway events. |
| `policy` | `Optional[dict]` | `None` | Optional parsed policy dictionary. |

### `NodeGateway` Methods

| Method & Signature | Expected Inputs | Return Value / Output | Rejection & Security Behavior |
| :--- | :--- | :--- | :--- |
| `register_peer(peer: PeerInfo)` | `PeerInfo` of remote node | `None` | Stores peer keys for handshake verification |
| `apply_revocation(notice, authority_public_key_bytes)` | `RevocationNotice` and Authority DER/raw public key | `True` if signature valid and applied; `False` otherwise | Drops active sessions with `notice.node_id`, caches blocklist, logs `REVOCATION_ENFORCED`, records ack |
| `initiate_handshake(peer_node_id, epoch)` | Registered `peer_node_id` and active `epoch` | `Tuple[bytes, bytes, bytes, bytes]` (`kem_ct, eph_pub, transcript_sig, session_id`) | Raises `PermissionError` if peer/self revoked; `ValueError` on invalid epoch or unknown peer |
| `complete_handshake(peer_node_id, kem_ciphertext, ephemeral_x25519_public_bytes, peer_signature, epoch)` | Initiator handshake payload | `session_id: bytes` (`32` bytes matching initiator) | Raises `PermissionError` if revoked; `ValueError` on invalid epoch or signature failure (`HANDSHAKE_SIG_FAIL`) |
| `send_message(session_id, plaintext, recipient_node_id)` | Active `session_id`, payload `bytes`, recipient ID | `TransferResult` (`success=True` + `encrypted_chunks` list) | Returns `TransferResult(success=False, error=...)` if session unknown, peer revoked, or epoch expired; increments `next_send_seq` per `64 KB` chunk |
| `receive_chunk(session_id, nonce, ciphertext, aad_json, seq_num)` | Encrypted chunk fields and sequence number | Full reassembled `bytes` when final chunk arrives; `None` while pending or on rejection | Rejects and logs on unknown session, revoked peer, expired epoch, replay (`is_acceptable`), AAD mismatch (`sender`/`recipient`/`epoch`/`seq`), `InvalidTag`, or bad chunk index; mutates `anti_replay` only after tag verification |
| `create_resumption_ticket(session_id, signing_key_bytes=None, master_kek=None)` | Active `session_id`; optional external keys (defaults to node-local keys) | Serialized signed + encrypted ticket `bytes` | Raises `ValueError` on unknown `session_id`; embeds unique `jti`, `peer_id`, `epoch`, `expiry` (`3,600 s`) |
| `resume_session(ticket_bytes, claiming_peer_id, verify_key_bytes=None, master_kek=None)` | Ticket `bytes` and `claiming_peer_id` | New `session_id: bytes` on success; `None` on failure | Verifies `ML-DSA-65` signature (`CTX_RESUMPTION`) before decryption; rejects revoked peers, expired tickets, peer mismatches, expired epochs, and replayed `jti`s |
| `cleanup_stale_sessions(reassembly_timeout_seconds=30.0, session_ttl_seconds=3600)` | Timeout thresholds in seconds | `int` count of purged sessions and timed-out incomplete buffers | Logs `SESSION_EXPIRED` and `REASSEMBLY_TIMEOUT` |
