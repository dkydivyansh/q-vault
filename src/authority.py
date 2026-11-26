"""
authority.py — Q-Vault Sentinel Key & Identity Authority

Central control plane managing node registrations, scheduled epoch rotations,
signed revocation broadcasts, atomic SQLite WAL state persistence, and encrypted,
ML-DSA-65 signed key backups.
"""

import hashlib
import json
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CTX_EPOCH = b"qvault-epoch-v1"
CTX_REVOKE = b"qvault-revoke-v1"
CTX_BACKUP = b"qvault-backup-v1"

MLDSA65_PUBKEY_BYTES = 1952
MLKEM768_PUBKEY_BYTES = 1184
X25519_PUBKEY_BYTES = 32


@dataclass
class NodeRecord:
    """Registered service node identity and revocation state."""

    node_id: str
    signing_public_bytes: bytes
    kem_public_bytes: bytes
    x25519_public_bytes: bytes
    key_epoch: int
    registered_at: float
    is_revoked: bool = False
    revoked_at: Optional[float] = None


@dataclass
class RotationEpoch:
    """Signed epoch announcement defining grace window and hard cutoff."""

    epoch: int
    valid_from: float
    grace_until: float
    cutoff: float
    signature: bytes


@dataclass
class RevocationNotice:
    """Signed revocation directive and per-node acknowledgment timestamps."""

    node_id: str
    revocation_epoch: int
    revoked_at: float
    reason: str
    signature: bytes
    propagation_times: Dict[str, float] = field(default_factory=dict)


class KeyAuthority:
    """SQLite WAL-backed key authority for node identities, rotations, and revocations."""

    def __init__(
        self,
        db_path: str,
        master_kek_hex: str,
        grace_period_seconds: float = 30.0,
    ) -> None:
        raw_kek = bytes.fromhex(master_kek_hex)
        if len(raw_kek) != 32:
            raise ValueError(f"master_kek must be 32 bytes; got {len(raw_kek)}")
        self._master_kek: bytes = raw_kek
        self._db_path: str = db_path

        self._conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        self._init_db()

        self._grace_period: float = grace_period_seconds
        self._current_epoch: int = 0
        self._revocation_epoch: int = 0
        self._node_callbacks: List[Callable] = []
        self._lock: threading.RLock = threading.RLock()
        self._active_revocations: Dict[int, RevocationNotice] = {}

        self._auth_signing_private: mldsa.MLDSAPrivateKey
        self._auth_signing_public: mldsa.MLDSAPublicKey
        self._load_or_generate_authority_keys()

        self._reload_epoch_counter()
        self._reload_revocation_counter()

    def _init_db(self) -> None:
        with self._conn:
            # Acquire write lock up front so concurrent writers serialize cleanly.
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id        TEXT PRIMARY KEY,
                    signing_public BLOB NOT NULL,
                    kem_public     BLOB NOT NULL,
                    x25519_public  BLOB NOT NULL,
                    key_epoch      INTEGER NOT NULL,
                    registered_at  REAL NOT NULL,
                    is_revoked     INTEGER NOT NULL DEFAULT 0,
                    revoked_at     REAL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS epochs (
                    epoch       INTEGER PRIMARY KEY,
                    valid_from  REAL NOT NULL,
                    grace_until REAL NOT NULL,
                    cutoff      REAL NOT NULL,
                    signature   BLOB NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS revocations (
                    node_id           TEXT NOT NULL,
                    revocation_epoch  INTEGER NOT NULL,
                    revoked_at        REAL NOT NULL,
                    reason            TEXT NOT NULL,
                    signature         BLOB NOT NULL,
                    PRIMARY KEY (node_id, revocation_epoch)
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS ack_log (
                    node_id           TEXT NOT NULL,
                    revocation_epoch  INTEGER NOT NULL,
                    acked_at          REAL NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS authority_keys (
                    id          INTEGER PRIMARY KEY CHECK (id = 1),
                    nonce       BLOB NOT NULL,
                    ciphertext  BLOB NOT NULL
                )
            """)
            self._conn.execute("COMMIT")

    def _load_or_generate_authority_keys(self) -> None:
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM authority_keys WHERE id = 1"
        ).fetchone()

        if row is None:
            private_key = mldsa.generate_private_key(mldsa.MLDSA65())
            private_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(self._master_kek).encrypt(nonce, private_der, None)

            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO authority_keys (id, nonce, ciphertext) VALUES (1, ?, ?)",
                    (nonce, ciphertext),
                )
                self._conn.execute("COMMIT")

            self._auth_signing_private = private_key
            self._auth_signing_public = private_key.public_key()
        else:
            nonce, ciphertext = row
            try:
                private_der = AESGCM(self._master_kek).decrypt(
                    bytes(nonce), bytes(ciphertext), None
                )
            except InvalidTag as exc:
                raise ValueError(
                    "Master KEK did not authenticate the stored authority key — "
                    "wrong KEK or corrupted database row."
                ) from exc

            private_key = serialization.load_der_private_key(private_der, password=None)
            self._auth_signing_private = private_key  # type: ignore[assignment]
            self._auth_signing_public = private_key.public_key()

    def _reload_epoch_counter(self) -> None:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(epoch), 0) FROM epochs"
        ).fetchone()
        self._current_epoch = row[0] if row else 0

    def _reload_revocation_counter(self) -> None:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(revocation_epoch), 0) FROM revocations"
        ).fetchone()
        self._revocation_epoch = row[0] if row else 0

    def _sign(self, payload: bytes, context: bytes) -> bytes:
        return self._auth_signing_private.sign(payload, context)

    def _verify_own_signature(
        self, payload: bytes, signature: bytes, context: bytes
    ) -> bool:
        try:
            self._auth_signing_public.verify(signature, payload, context)
            return True
        except Exception:
            return False

    def register_node(
        self,
        node_id: str,
        signing_public_bytes: bytes,
        kem_public_bytes: bytes,
        x25519_public_bytes: bytes,
    ) -> NodeRecord:
        """Validate public key sizes and register a new node atomically."""
        if len(signing_public_bytes) != MLDSA65_PUBKEY_BYTES:
            raise ValueError(
                f"ML-DSA-65 public key must be {MLDSA65_PUBKEY_BYTES} bytes; "
                f"got {len(signing_public_bytes)}"
            )
        if len(kem_public_bytes) != MLKEM768_PUBKEY_BYTES:
            raise ValueError(
                f"ML-KEM-768 public key must be {MLKEM768_PUBKEY_BYTES} bytes; "
                f"got {len(kem_public_bytes)}"
            )
        if len(x25519_public_bytes) != X25519_PUBKEY_BYTES:
            raise ValueError(
                f"X25519 public key must be {X25519_PUBKEY_BYTES} bytes; "
                f"got {len(x25519_public_bytes)}"
            )

        registered_at = time.time()

        with self._lock:
            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    self._conn.execute(
                        """
                        INSERT INTO nodes
                            (node_id, signing_public, kem_public, x25519_public,
                             key_epoch, registered_at, is_revoked, revoked_at)
                        VALUES (?, ?, ?, ?, ?, ?, 0, NULL)
                        """,
                        (
                            node_id,
                            signing_public_bytes,
                            kem_public_bytes,
                            x25519_public_bytes,
                            self._current_epoch,
                            registered_at,
                        ),
                    )
                    self._conn.execute("COMMIT")
                except sqlite3.IntegrityError as exc:
                    self._conn.execute("ROLLBACK")
                    raise ValueError(
                        f"Node '{node_id}' is already registered."
                    ) from exc

        return NodeRecord(
            node_id=node_id,
            signing_public_bytes=signing_public_bytes,
            kem_public_bytes=kem_public_bytes,
            x25519_public_bytes=x25519_public_bytes,
            key_epoch=self._current_epoch,
            registered_at=registered_at,
        )

    def rotate_keys(
        self, announce_callback: Optional[Callable] = None
    ) -> RotationEpoch:
        """Advance key epoch, persist grace window atomically, and emit signed announcement."""
        with self._lock:
            self._current_epoch += 1
            new_epoch = self._current_epoch

            now = time.time()
            valid_from = now
            grace_until = now + self._grace_period
            cutoff = grace_until

            announcement = json.dumps(
                {
                    "epoch": new_epoch,
                    "valid_from": valid_from,
                    "grace_until": grace_until,
                    "cutoff": cutoff,
                },
                sort_keys=True,
            ).encode()

            signature = self._sign(announcement, CTX_EPOCH)

            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    """
                    INSERT INTO epochs (epoch, valid_from, grace_until, cutoff, signature)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (new_epoch, valid_from, grace_until, cutoff, signature),
                )
                self._conn.execute("COMMIT")

            rotation = RotationEpoch(
                epoch=new_epoch,
                valid_from=valid_from,
                grace_until=grace_until,
                cutoff=cutoff,
                signature=signature,
            )

        # Invoke callback outside self._lock to avoid deadlock on re-entrant authority queries.
        if announce_callback is not None:
            announce_callback(rotation)

        return rotation

    def is_epoch_valid(
        self, epoch: int, check_time: Optional[float] = None
    ) -> bool:
        """Return True if `epoch` is active or within its post-rotation grace window."""
        t = check_time if check_time is not None else time.time()

        with self._lock:
            current = self._current_epoch

        if epoch == current:
            return True

        if epoch == current - 1:
            row = self._conn.execute(
                "SELECT grace_until FROM epochs WHERE epoch = ?",
                (epoch,),
            ).fetchone()
            if row is None:
                return False
            grace_until: float = row[0]
            return t < grace_until

        return False

    def revoke_node(
        self, node_id: str, reason: str = "operator-triggered"
    ) -> RevocationNotice:
        """Persist node revocation atomically and broadcast signed RevocationNotice."""
        with self._lock:
            row = self._conn.execute(
                "SELECT is_revoked FROM nodes WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Node '{node_id}' is not registered.")

            self._revocation_epoch += 1
            rev_epoch = self._revocation_epoch
            revoked_at = time.time()

            payload = json.dumps(
                {
                    "node_id": node_id,
                    "revocation_epoch": rev_epoch,
                    "revoked_at": revoked_at,
                    "reason": reason,
                },
                sort_keys=True,
            ).encode()

            signature = self._sign(payload, CTX_REVOKE)

            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "UPDATE nodes SET is_revoked = 1, revoked_at = ? WHERE node_id = ?",
                    (revoked_at, node_id),
                )
                self._conn.execute(
                    """
                    INSERT INTO revocations
                        (node_id, revocation_epoch, revoked_at, reason, signature)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (node_id, rev_epoch, revoked_at, reason, signature),
                )
                self._conn.execute("COMMIT")

            notice = RevocationNotice(
                node_id=node_id,
                revocation_epoch=rev_epoch,
                revoked_at=revoked_at,
                reason=reason,
                signature=signature,
            )

            self._active_revocations[rev_epoch] = notice
            callbacks = list(self._node_callbacks)

        # Invoke callbacks outside self._lock to prevent re-entrant lock deadlocks.
        for cb in callbacks:
            try:
                cb(notice)
            except Exception:
                pass

        return notice

    def is_revoked(self, node_id: str) -> bool:
        """Return persistent revocation status for `node_id`."""
        row = self._conn.execute(
            "SELECT is_revoked FROM nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return False
        return bool(row[0])

    def record_revocation_ack(
        self, node_id: str, revocation_epoch: int, acked_at: float
    ) -> None:
        """Persist a node's revocation acknowledgment for latency tracking."""
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO ack_log (node_id, revocation_epoch, acked_at) VALUES (?, ?, ?)",
                (node_id, revocation_epoch, acked_at),
            )
            self._conn.execute("COMMIT")

        with self._lock:
            notice = self._active_revocations.get(revocation_epoch)
            if notice is not None:
                notice.propagation_times[node_id] = acked_at

    def get_propagation_stats(self, revocation_epoch: int) -> dict:
        """Compute min/max propagation latency across acknowledgments for `revocation_epoch`."""
        rev_row = self._conn.execute(
            "SELECT revoked_at FROM revocations WHERE revocation_epoch = ?",
            (revocation_epoch,),
        ).fetchone()
        revoked_at: float = rev_row[0] if rev_row else 0.0

        rows = self._conn.execute(
            "SELECT node_id, acked_at FROM ack_log WHERE revocation_epoch = ?",
            (revocation_epoch,),
        ).fetchall()

        all_acks = []
        propagation_ms_values = []
        for node_id, acked_at in rows:
            prop_ms = (acked_at - revoked_at) * 1000.0
            propagation_ms_values.append(prop_ms)
            all_acks.append(
                {
                    "node_id": node_id,
                    "acked_at": acked_at,
                    "propagation_ms": prop_ms,
                }
            )

        total_acked = len(propagation_ms_values)
        max_prop_ms = max(propagation_ms_values) if propagation_ms_values else 0.0
        min_prop_ms = min(propagation_ms_values) if propagation_ms_values else 0.0

        return {
            "revocation_epoch": revocation_epoch,
            "total_acked": total_acked,
            "max_propagation_ms": max_prop_ms,
            "min_propagation_ms": min_prop_ms,
            "all_acks": all_acks,
        }

    def register_revocation_callback(self, callback: Callable) -> None:
        """Register a listener invoked with RevocationNotice on node revocation."""
        with self._lock:
            self._node_callbacks.append(callback)

    def backup_keys(self, backup_path: str) -> dict:
        """Encrypt authority private key with master KEK, checksum, and sign with ML-DSA-65."""
        private_der = self._auth_signing_private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        checksum = hashlib.sha256(private_der).digest()
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._master_kek).encrypt(nonce, private_der, None)

        ct_length = struct.pack(">I", len(ciphertext))
        unsigned_payload = nonce + checksum + ct_length + ciphertext
        signature = self._sign(unsigned_payload, CTX_BACKUP)

        full_backup = unsigned_payload + signature
        backup_file = Path(backup_path)
        backup_file.parent.mkdir(parents=True, exist_ok=True)

        tmp_path = backup_file.with_suffix(".tmp")
        tmp_path.write_bytes(full_backup)
        tmp_path.replace(backup_file)

        return {
            "path": str(backup_file.resolve()),
            "checksum": checksum.hex(),
            "size": len(full_backup),
        }

    def restore_from_backup(self, backup_path: str) -> bool:
        """Verify backup signature, decrypt with master KEK, validate checksum, and restore."""
        raw = Path(backup_path).read_bytes()

        if len(raw) < 48:
            raise ValueError(
                f"Backup file too small ({len(raw)} bytes); corrupted or wrong file."
            )

        nonce = raw[0:12]
        expected_checksum = raw[12:44]
        (ct_length,) = struct.unpack(">I", raw[44:48])

        if len(raw) < 48 + ct_length:
            raise ValueError(
                f"Backup file truncated: expected at least {48 + ct_length} bytes, "
                f"got {len(raw)}."
            )

        ciphertext = raw[48 : 48 + ct_length]
        signature = raw[48 + ct_length :]
        unsigned_payload = raw[: 48 + ct_length]

        # Verify ML-DSA-65 signature before attempting decryption to prevent oracle attacks.
        if not self._verify_own_signature(unsigned_payload, signature, CTX_BACKUP):
            raise ValueError(
                "ML-DSA-65 signature verification failed — backup is tampered or "
                "was not produced by this authority."
            )

        try:
            private_der = AESGCM(self._master_kek).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "AES-256-GCM decryption failed — wrong KEK or corrupted ciphertext."
            ) from exc

        actual_checksum = hashlib.sha256(private_der).digest()
        if not secrets.compare_digest(actual_checksum, expected_checksum):
            raise ValueError(
                "SHA-256 checksum mismatch after decryption — backup is corrupted."
            )

        try:
            private_key = serialization.load_der_private_key(private_der, password=None)
        except Exception as exc:
            raise ValueError(
                f"Failed to deserialise private key from backup DER: {exc}"
            ) from exc

        new_nonce = secrets.token_bytes(12)
        new_ciphertext = AESGCM(self._master_kek).encrypt(new_nonce, private_der, None)

        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT OR REPLACE INTO authority_keys (id, nonce, ciphertext) VALUES (1, ?, ?)",
                (new_nonce, new_ciphertext),
            )
            self._conn.execute("COMMIT")

        with self._lock:
            self._auth_signing_private = private_key  # type: ignore[assignment]
            self._auth_signing_public = private_key.public_key()

        return True

    def get_node(self, node_id: str) -> Optional[NodeRecord]:
        """Return NodeRecord for `node_id`, or None if unregistered."""
        row = self._conn.execute(
            """
            SELECT node_id, signing_public, kem_public, x25519_public,
                   key_epoch, registered_at, is_revoked, revoked_at
            FROM nodes
            WHERE node_id = ?
            """,
            (node_id,),
        ).fetchone()

        if row is None:
            return None

        return NodeRecord(
            node_id=row[0],
            signing_public_bytes=bytes(row[1]),
            kem_public_bytes=bytes(row[2]),
            x25519_public_bytes=bytes(row[3]),
            key_epoch=row[4],
            registered_at=row[5],
            is_revoked=bool(row[6]),
            revoked_at=row[7],
        )

    def list_nodes(self, include_revoked: bool = False) -> List[NodeRecord]:
        """Return registered NodeRecord entries ordered by registration timestamp."""
        if include_revoked:
            query = """
                SELECT node_id, signing_public, kem_public, x25519_public,
                       key_epoch, registered_at, is_revoked, revoked_at
                FROM nodes
                ORDER BY registered_at ASC
            """
        else:
            query = """
                SELECT node_id, signing_public, kem_public, x25519_public,
                       key_epoch, registered_at, is_revoked, revoked_at
                FROM nodes
                WHERE is_revoked = 0
                ORDER BY registered_at ASC
            """
        rows = self._conn.execute(query).fetchall()

        return [
            NodeRecord(
                node_id=row[0],
                signing_public_bytes=bytes(row[1]),
                kem_public_bytes=bytes(row[2]),
                x25519_public_bytes=bytes(row[3]),
                key_epoch=row[4],
                registered_at=row[5],
                is_revoked=bool(row[6]),
                revoked_at=row[7],
            )
            for row in rows
        ]

    def get_authority_public_key_bytes(self) -> bytes:
        """Return DER-encoded ML-DSA-65 public key for offline signature verification."""
        return self._auth_signing_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def close(self) -> None:
        """Checkpoint WAL frames and close the SQLite database connection."""
        self._conn.execute("PRAGMA wal_checkpoint(FULL)")
        self._conn.close()
