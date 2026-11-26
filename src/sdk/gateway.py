"""
gateway.py — Q-Vault Sentinel Quantum-Safe Node Gateway

Data-plane proxy/SDK for protected service endpoints implementing:
  - Hybrid forward-secret handshakes (X25519 + ML-KEM-768, ML-DSA-65 auth)
  - AES-256-GCM encryption with AAD recipient binding
  - Sliding-bitmask anti-replay enforcement
  - Chunking and ordered payload reassembly
  - Peer-bound session resumption tickets
  - Cross-node signed revocation enforcement
  - AuditLedger event emission
"""

import hashlib
import json
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_engine import (
    CTX_HANDSHAKE,
    CTX_RESUMPTION,
    CTX_REVOKE,
    load_mldsa_public_key,
    load_mlkem_public_key,
)

REPLAY_WINDOW_SIZE = 1024
MAX_CHUNK_SIZE = 65536
SESSION_RESUMPTION_TTL = 3600
MAX_REASSEMBLY_TIMEOUT = 30.0


@dataclass
class PeerInfo:
    """Public identity keys for a registered peer service node."""

    node_id: str
    signing_public_bytes: bytes
    kem_public_bytes: bytes
    x25519_public_bytes: bytes


class AntiReplayWindow:
    """Sliding bitmask window tracking seen sequence numbers over [_base_seq, _base_seq + window_size)."""

    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE):
        self._window_size = window_size
        self._base_seq: int = 0
        self._bitmask: int = 0

    def is_acceptable(self, seq_num: int) -> bool:
        """Check without mutating state whether `seq_num` is unseen and within window."""
        if seq_num < self._base_seq:
            return False
        if seq_num >= self._base_seq + self._window_size:
            return True
        bit_pos = seq_num - self._base_seq
        return not bool(self._bitmask & (1 << bit_pos))

    def record(self, seq_num: int) -> None:
        """Advance window if needed and mark an authenticated `seq_num` as seen."""
        if seq_num >= self._base_seq + self._window_size:
            shift = seq_num - (self._base_seq + self._window_size - 1)
            self._bitmask <<= shift
            self._base_seq += shift
            # Keep bitmask bounded to window_size bits.
            self._bitmask &= (1 << self._window_size) - 1
        bit_pos = seq_num - self._base_seq
        self._bitmask |= 1 << bit_pos

    def check_and_record(self, seq_num: int) -> bool:
        """Return True and record `seq_num` if unseen; return False on replay or stale packet."""
        if not self.is_acceptable(seq_num):
            return False
        self.record(seq_num)
        return True


@dataclass
class ActiveSession:
    """Cryptographic session state and in-flight chunk reassembly buffers."""

    session_id: bytes
    peer_node_id: str
    aes_key: bytes
    epoch: int
    created_at: float
    last_used: float = field(default_factory=time.time)
    next_send_seq: int = 0
    anti_replay: AntiReplayWindow = field(default_factory=AntiReplayWindow)
    in_flight: Dict[str, dict] = field(default_factory=dict)


@dataclass
class TransferResult:
    """Outcome summary of an encrypted chunked transfer."""

    msg_id: str
    success: bool
    chunks_sent: int
    chunks_received: int
    delivery_ms: float
    error: Optional[str] = None


class NodeGateway:
    """Quantum-safe service-node gateway handling handshakes, chunking, and resumption."""

    def __init__(
        self,
        node_id: str,
        keypair_private_key_bytes: dict,
        authority_client=None,
        ledger=None,
        policy: dict = None,
    ):
        self._node_id = node_id
        self._signing_private: mldsa.MLDSAPrivateKey = (
            serialization.load_der_private_key(
                keypair_private_key_bytes["mldsa_private"], password=None
            )
        )
        self._kem_private: mlkem.MLKEMPrivateKey = (
            serialization.load_der_private_key(
                keypair_private_key_bytes["mlkem_private"], password=None
            )
        )
        self._x25519_private: X25519PrivateKey = X25519PrivateKey.from_private_bytes(
            keypair_private_key_bytes["x25519_private"]
        )

        self._sessions: Dict[bytes, ActiveSession] = {}
        self._resumption_tickets: Dict[bytes, dict] = {}
        self._consumed_ticket_ids: Set[str] = set()
        self._ticket_kek: bytes = secrets.token_bytes(32)
        self._peers: Dict[str, PeerInfo] = {}
        self._revoked_peers: Set[str] = set()
        self._authority_client = authority_client
        self._ledger = ledger
        self._lock = threading.RLock()
        self._policy = policy or {}

    @property
    def node_id(self) -> str:
        return self._node_id

    def register_peer(self, peer: PeerInfo) -> None:
        """Register public identity keys for a remote peer."""
        with self._lock:
            self._peers[peer.node_id] = peer

    def _log(self, action: str, target: str, details: dict) -> None:
        if self._ledger:
            self._ledger.log(
                actor=self._node_id,
                action=action,
                target=target,
                details=details,
            )

    def _is_peer_revoked(self, peer_node_id: str) -> bool:
        if peer_node_id in self._revoked_peers or self._node_id in self._revoked_peers:
            return True
        if self._authority_client is not None:
            if self._authority_client.is_revoked(peer_node_id) or self._authority_client.is_revoked(self._node_id):
                return True
        return False

    def _is_epoch_acceptable(self, epoch: int) -> bool:
        if self._authority_client is None:
            return True
        return self._authority_client.is_epoch_valid(epoch)

    def apply_revocation(
        self, notice, authority_public_key_bytes: bytes
    ) -> bool:
        """Verify signed RevocationNotice, enforce blocklist across sessions, and acknowledge."""
        payload = json.dumps(
            {
                "node_id": notice.node_id,
                "revocation_epoch": notice.revocation_epoch,
                "revoked_at": notice.revoked_at,
                "reason": notice.reason,
            },
            sort_keys=True,
        ).encode()

        verify_key = load_mldsa_public_key(authority_public_key_bytes)
        try:
            verify_key.verify(notice.signature, payload, context=CTX_REVOKE)
        except Exception:
            return False

        with self._lock:
            self._revoked_peers.add(notice.node_id)
            terminated = [
                sid
                for sid, sess in self._sessions.items()
                if sess.peer_node_id == notice.node_id or notice.node_id == self._node_id
            ]
            for sid in terminated:
                self._sessions.pop(sid, None)
                self._resumption_tickets.pop(sid, None)

        self._log(
            action="REVOCATION_ENFORCED",
            target=notice.node_id,
            details={
                "revocation_epoch": notice.revocation_epoch,
                "terminated_sessions": len(terminated),
                "reason": notice.reason,
            },
        )

        if self._authority_client is not None:
            self._authority_client.record_revocation_ack(
                self._node_id, notice.revocation_epoch, time.time()
            )
        return True

    def _derive_session_key(
        self,
        kem_shared: bytes,
        x25519_shared: bytes,
        salt: bytes,
        info: bytes,
    ) -> bytes:
        ikm = kem_shared + x25519_shared
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)

    def _build_handshake_transcript(
        self,
        initiator_id: str,
        responder_id: str,
        kem_ciphertext: bytes,
        ephemeral_x25519_public_bytes: bytes,
        epoch: int,
    ) -> bytes:
        transcript_dict = {
            "initiator": initiator_id,
            "responder": responder_id,
            "kem_ciphertext_hash": hashlib.sha256(kem_ciphertext).hexdigest(),
            "ephemeral_x25519_pub": ephemeral_x25519_public_bytes.hex(),
            "epoch": epoch,
        }
        return json.dumps(transcript_dict, sort_keys=True).encode()

    def initiate_handshake(
        self, peer_node_id: str, epoch: int
    ) -> Tuple[bytes, bytes, bytes, bytes]:
        """Initiate hybrid handshake; returns (kem_ct, eph_x25519_pub, transcript_sig, session_id)."""
        with self._lock:
            if self._is_peer_revoked(peer_node_id):
                raise PermissionError(f"Handshake blocked: revoked identity ({peer_node_id})")
            if not self._is_epoch_acceptable(epoch):
                raise ValueError(f"Handshake rejected: expired or invalid epoch {epoch}")
            if peer_node_id not in self._peers:
                raise ValueError(f"Unknown peer: {peer_node_id}")
            peer = self._peers[peer_node_id]

            peer_kem_pub: mlkem.MLKEM768PublicKey = load_mlkem_public_key(peer.kem_public_bytes)
            # cryptography>=50 encapsulate() returns (shared_secret, ciphertext).
            kem_shared, kem_ct = peer_kem_pub.encapsulate()

            ephemeral_x25519_priv: Optional[X25519PrivateKey] = X25519PrivateKey.generate()
            ephemeral_x25519_pub_bytes: bytes = (
                ephemeral_x25519_priv.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            )

            peer_x25519_pub: X25519PublicKey = X25519PublicKey.from_public_bytes(
                peer.x25519_public_bytes
            )
            x25519_shared: bytes = ephemeral_x25519_priv.exchange(peer_x25519_pub)
            # Clear ephemeral key reference immediately after DH exchange (FIPS 204 §3.6.3).
            ephemeral_x25519_priv = None

            salt = hashlib.sha256(
                ephemeral_x25519_pub_bytes + peer.x25519_public_bytes
            ).digest()
            session_key = self._derive_session_key(
                kem_shared,
                x25519_shared,
                salt=salt,
                info=b"qvault-session-key-v1",
            )

            transcript = self._build_handshake_transcript(
                initiator_id=self._node_id,
                responder_id=peer_node_id,
                kem_ciphertext=kem_ct,
                ephemeral_x25519_public_bytes=ephemeral_x25519_pub_bytes,
                epoch=epoch,
            )
            transcript_signature: bytes = self._signing_private.sign(
                transcript,
                context=CTX_HANDSHAKE,
            )
            session_id = hashlib.sha256(session_key + transcript).digest()

            session = ActiveSession(
                session_id=session_id,
                peer_node_id=peer_node_id,
                aes_key=session_key,
                epoch=epoch,
                created_at=time.time(),
            )
            self._sessions[session_id] = session

            self._log(
                action="HANDSHAKE_INIT",
                target=peer_node_id,
                details={
                    "session_id": session_id.hex(),
                    "epoch": epoch,
                    "kem_ct_hash": hashlib.sha256(kem_ct).hexdigest(),
                },
            )

            return kem_ct, ephemeral_x25519_pub_bytes, transcript_signature, session_id

    def complete_handshake(
        self,
        peer_node_id: str,
        kem_ciphertext: bytes,
        ephemeral_x25519_public_bytes: bytes,
        peer_signature: bytes,
        epoch: int,
    ) -> bytes:
        """Complete incoming handshake, verify ML-DSA-65 transcript signature, and return session_id."""
        with self._lock:
            if self._is_peer_revoked(peer_node_id):
                raise PermissionError(f"Handshake blocked: revoked identity ({peer_node_id})")
            if not self._is_epoch_acceptable(epoch):
                raise ValueError(f"Handshake rejected: expired or invalid epoch {epoch}")
            if peer_node_id not in self._peers:
                raise ValueError(f"Unknown peer: {peer_node_id}")
            peer = self._peers[peer_node_id]

            kem_shared: bytes = self._kem_private.decapsulate(kem_ciphertext)
            peer_ephemeral_x25519_pub: X25519PublicKey = (
                X25519PublicKey.from_public_bytes(ephemeral_x25519_public_bytes)
            )
            x25519_shared: bytes = self._x25519_private.exchange(
                peer_ephemeral_x25519_pub
            )

            # Mirror initiator salt order: initiator_ephemeral_pub || responder_static_pub.
            our_x25519_pub_bytes: bytes = self._x25519_private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            salt = hashlib.sha256(
                ephemeral_x25519_public_bytes + our_x25519_pub_bytes
            ).digest()

            session_key = self._derive_session_key(
                kem_shared,
                x25519_shared,
                salt=salt,
                info=b"qvault-session-key-v1",
            )

            transcript = self._build_handshake_transcript(
                initiator_id=peer_node_id,
                responder_id=self._node_id,
                kem_ciphertext=kem_ciphertext,
                ephemeral_x25519_public_bytes=ephemeral_x25519_public_bytes,
                epoch=epoch,
            )

            peer_signing_pub: mldsa.MLDSA65PublicKey = load_mldsa_public_key(
                peer.signing_public_bytes
            )

            try:
                peer_signing_pub.verify(
                    peer_signature,
                    transcript,
                    context=CTX_HANDSHAKE,
                )
            except Exception as exc:
                self._log(
                    action="HANDSHAKE_SIG_FAIL",
                    target=peer_node_id,
                    details={"reason": str(exc), "epoch": epoch},
                )
                raise ValueError(
                    f"Handshake signature verification failed for peer {peer_node_id}: {exc}"
                ) from exc

            session_id = hashlib.sha256(session_key + transcript).digest()
            session = ActiveSession(
                session_id=session_id,
                peer_node_id=peer_node_id,
                aes_key=session_key,
                epoch=epoch,
                created_at=time.time(),
            )
            self._sessions[session_id] = session

            self._log(
                action="HANDSHAKE_COMPLETE",
                target=peer_node_id,
                details={"session_id": session_id.hex(), "epoch": epoch},
            )

            return session_id

    def send_message(
        self,
        session_id: bytes,
        plaintext: bytes,
        recipient_node_id: str,
    ) -> TransferResult:
        """Chunk and AES-256-GCM encrypt `plaintext` with recipient-bound AAD."""
        start_time = time.time()

        with self._lock:
            if session_id not in self._sessions:
                return TransferResult(
                    msg_id="",
                    success=False,
                    chunks_sent=0,
                    chunks_received=0,
                    delivery_ms=0.0,
                    error="Unknown session_id",
                )

            session = self._sessions[session_id]
            if self._is_peer_revoked(recipient_node_id):
                return TransferResult(
                    msg_id="",
                    success=False,
                    chunks_sent=0,
                    chunks_received=0,
                    delivery_ms=0.0,
                    error=f"Peer '{recipient_node_id}' is revoked",
                )
            if not self._is_epoch_acceptable(session.epoch):
                return TransferResult(
                    msg_id="",
                    success=False,
                    chunks_sent=0,
                    chunks_received=0,
                    delivery_ms=0.0,
                    error=f"Session epoch {session.epoch} expired past grace cutoff",
                )

            session.last_used = time.time()
            msg_id = secrets.token_hex(16)
            chunks: List[bytes] = [
                plaintext[i : i + MAX_CHUNK_SIZE]
                for i in range(0, max(len(plaintext), 1), MAX_CHUNK_SIZE)
            ]
            total_chunks = len(chunks)
            aesgcm = AESGCM(session.aes_key)
            encrypted_chunks: List[dict] = []

            for i, chunk_plaintext in enumerate(chunks):
                seq_num = session.next_send_seq
                session.next_send_seq += 1

                aad = json.dumps(
                    {
                        "sender": self._node_id,
                        "recipient": recipient_node_id,
                        "epoch": session.epoch,
                        "msg_id": msg_id,
                        "chunk_idx": i,
                        "total_chunks": total_chunks,
                        "seq": seq_num,
                    },
                    sort_keys=True,
                ).encode()

                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, chunk_plaintext, aad)

                encrypted_chunks.append(
                    {
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                        "aad": aad.decode(),
                        "seq_num": seq_num,
                    }
                )

            self._log(
                action="MESSAGE_SEND",
                target=recipient_node_id,
                details={
                    "session_id": session_id.hex(),
                    "msg_id": msg_id,
                    "total_chunks": total_chunks,
                    "total_bytes": len(plaintext),
                },
            )

            delivery_ms = (time.time() - start_time) * 1000.0
            result = TransferResult(
                msg_id=msg_id,
                success=True,
                chunks_sent=total_chunks,
                chunks_received=0,
                delivery_ms=delivery_ms,
            )
            result.encrypted_chunks = encrypted_chunks  # type: ignore[attr-defined]
            return result

    def receive_chunk(
        self,
        session_id: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad_json: str,
        seq_num: int,
    ) -> Optional[bytes]:
        """Validate anti-replay and recipient binding, decrypt chunk, and reassemble complete messages."""
        with self._lock:
            if session_id not in self._sessions:
                self._log(
                    action="RECEIVE_UNKNOWN_SESSION",
                    target="unknown",
                    details={"session_id": session_id.hex(), "seq": seq_num},
                )
                return None

            session = self._sessions[session_id]

            if self._is_peer_revoked(session.peer_node_id):
                self._log(
                    action="REVOKED_ACCESS_BLOCKED",
                    target=session.peer_node_id,
                    details={"session_id": session_id.hex(), "seq": seq_num},
                )
                return None

            if not self._is_epoch_acceptable(session.epoch):
                self._log(
                    action="EXPIRED_EPOCH_REJECTED",
                    target=session.peer_node_id,
                    details={"session_id": session_id.hex(), "epoch": session.epoch},
                )
                return None

            # Read-only anti-replay precheck drops duplicates before AES-GCM; window mutates only after tag authentication.
            if not session.anti_replay.is_acceptable(seq_num):
                self._log(
                    action="REPLAY_DETECTED",
                    target=session.peer_node_id,
                    details={
                        "session_id": session_id.hex(),
                        "seq": seq_num,
                    },
                )
                return None

            try:
                aad_dict = json.loads(aad_json)
            except json.JSONDecodeError:
                self._log(
                    action="RECEIVE_BAD_AAD",
                    target=session.peer_node_id,
                    details={"session_id": session_id.hex(), "seq": seq_num},
                )
                return None

            if (
                aad_dict.get("recipient") != self._node_id
                or aad_dict.get("sender") != session.peer_node_id
                or aad_dict.get("epoch") != session.epoch
                or aad_dict.get("seq") != seq_num
            ):
                self._log(
                    action="RECEIVE_AAD_BINDING_MISMATCH",
                    target=session.peer_node_id,
                    details={
                        "session_id": session_id.hex(),
                        "expected_recipient": self._node_id,
                        "got_recipient": aad_dict.get("recipient"),
                        "expected_sender": session.peer_node_id,
                        "got_sender": aad_dict.get("sender"),
                    },
                )
                return None

            aesgcm = AESGCM(session.aes_key)
            try:
                chunk_plaintext = aesgcm.decrypt(nonce, ciphertext, aad_json.encode())
            except InvalidTag:
                self._log(
                    action="RECEIVE_TAMPER_DETECTED",
                    target=session.peer_node_id,
                    details={
                        "session_id": session_id.hex(),
                        "seq": seq_num,
                        "msg_id": aad_dict.get("msg_id"),
                    },
                )
                return None

            session.anti_replay.record(seq_num)

            msg_id: str = aad_dict["msg_id"]
            chunk_idx: int = int(aad_dict["chunk_idx"])
            total_chunks: int = int(aad_dict["total_chunks"])

            if total_chunks <= 0 or chunk_idx < 0 or chunk_idx >= total_chunks:
                self._log(
                    action="RECEIVE_INVALID_CHUNK_INDEX",
                    target=session.peer_node_id,
                    details={"msg_id": msg_id, "chunk_idx": chunk_idx, "total_chunks": total_chunks},
                )
                return None

            if msg_id not in session.in_flight:
                session.in_flight[msg_id] = {
                    "chunks": {},
                    "total": total_chunks,
                    "received_at": time.time(),
                }

            session.in_flight[msg_id]["chunks"][chunk_idx] = chunk_plaintext
            session.last_used = time.time()

            in_flight_entry = session.in_flight[msg_id]
            if len(in_flight_entry["chunks"]) == in_flight_entry["total"]:
                reassembled = b"".join(
                    in_flight_entry["chunks"][idx]
                    for idx in range(in_flight_entry["total"])
                )
                del session.in_flight[msg_id]

                self._log(
                    action="MESSAGE_RECEIVED",
                    target=session.peer_node_id,
                    details={
                        "session_id": session_id.hex(),
                        "msg_id": msg_id,
                        "total_bytes": len(reassembled),
                    },
                )
                return reassembled

            return None

    def create_resumption_ticket(
        self,
        session_id: bytes,
        signing_key_bytes: Optional[bytes] = None,
        master_kek: Optional[bytes] = None,
    ) -> bytes:
        """Issue an encrypted, ML-DSA-65 signed, peer-bound single-use resumption ticket."""
        with self._lock:
            if session_id not in self._sessions:
                raise ValueError("Unknown session_id for resumption ticket")

            session = self._sessions[session_id]
            ticket_jti = secrets.token_hex(16)
            ticket_payload = json.dumps(
                {
                    "jti": ticket_jti,
                    "session_id": session_id.hex(),
                    "peer_id": session.peer_node_id,
                    "epoch": session.epoch,
                    "aes_key": session.aes_key.hex(),
                    "expiry": int(time.time()) + SESSION_RESUMPTION_TTL,
                },
                sort_keys=True,
            ).encode()

            kek = master_kek if master_kek is not None else self._ticket_kek
            ticket_nonce = secrets.token_bytes(12)
            encrypted_ticket = AESGCM(kek).encrypt(
                ticket_nonce, ticket_payload, None
            )

            if signing_key_bytes is not None:
                signing_key: mldsa.MLDSAPrivateKey = serialization.load_der_private_key(
                    signing_key_bytes, password=None
                )
            else:
                signing_key = self._signing_private

            ticket_to_sign = ticket_nonce + encrypted_ticket
            signature = signing_key.sign(
                ticket_to_sign,
                context=CTX_RESUMPTION,
            )

            sig_len = struct.pack(">I", len(signature))
            serialised = sig_len + signature + ticket_nonce + encrypted_ticket

            self._resumption_tickets[session_id] = {
                "jti": ticket_jti,
                "peer_id": session.peer_node_id,
                "expiry": int(time.time()) + SESSION_RESUMPTION_TTL,
            }

            self._log(
                action="RESUMPTION_TICKET_CREATED",
                target=session.peer_node_id,
                details={"session_id": session_id.hex()},
            )

            return serialised

    def resume_session(
        self,
        ticket_bytes: bytes,
        claiming_peer_id: str,
        verify_key_bytes: Optional[bytes] = None,
        master_kek: Optional[bytes] = None,
    ) -> Optional[bytes]:
        """Verify ticket signature, decrypt, validate expiry, single-use JTI, and peer binding."""
        with self._lock:
            try:
                if self._is_peer_revoked(claiming_peer_id):
                    self._log(
                        action="RESUMPTION_REVOKED_REJECTED",
                        target=claiming_peer_id,
                        details={},
                    )
                    return None

                if len(ticket_bytes) < 4:
                    raise ValueError("Ticket too short")

                (sig_len,) = struct.unpack(">I", ticket_bytes[:4])
                offset = 4

                if len(ticket_bytes) < offset + sig_len + 12:
                    raise ValueError("Ticket truncated before nonce")

                signature = ticket_bytes[offset : offset + sig_len]
                offset += sig_len

                ticket_nonce = ticket_bytes[offset : offset + 12]
                offset += 12

                encrypted_ticket = ticket_bytes[offset:]
                signed_blob = ticket_nonce + encrypted_ticket

                # Verify ML-DSA signature prior to AES-GCM decryption (fail-closed ordering).
                if verify_key_bytes is not None:
                    verify_key = load_mldsa_public_key(verify_key_bytes)
                else:
                    verify_key = self._signing_private.public_key()
                verify_key.verify(
                    signature,
                    signed_blob,
                    context=CTX_RESUMPTION,
                )

                kek = master_kek if master_kek is not None else self._ticket_kek
                ticket_payload = AESGCM(kek).decrypt(
                    ticket_nonce, encrypted_ticket, None
                )
                ticket_dict = json.loads(ticket_payload.decode())

                if int(time.time()) > ticket_dict["expiry"]:
                    self._log(
                        action="RESUMPTION_EXPIRED",
                        target=claiming_peer_id,
                        details={"expiry": ticket_dict["expiry"]},
                    )
                    return None

                if ticket_dict["peer_id"] != claiming_peer_id:
                    self._log(
                        action="RESUMPTION_HIJACK_REJECTED",
                        target=claiming_peer_id,
                        details={
                            "ticket_peer": ticket_dict["peer_id"],
                            "claiming_peer": claiming_peer_id,
                        },
                    )
                    return None

                ticket_jti = ticket_dict.get("jti", "")
                if not ticket_jti or ticket_jti in self._consumed_ticket_ids:
                    self._log(
                        action="RESUMPTION_REPLAY_REJECTED",
                        target=claiming_peer_id,
                        details={"jti": ticket_jti},
                    )
                    return None

                original_session_id = bytes.fromhex(ticket_dict["session_id"])
                aes_key = bytes.fromhex(ticket_dict["aes_key"])
                epoch = ticket_dict["epoch"]
                if not self._is_epoch_acceptable(epoch):
                    self._log(
                        action="RESUMPTION_EXPIRED_EPOCH",
                        target=claiming_peer_id,
                        details={"epoch": epoch},
                    )
                    return None

                self._consumed_ticket_ids.add(ticket_jti)
                new_session_id = secrets.token_bytes(32)
                self._sessions[new_session_id] = ActiveSession(
                    session_id=new_session_id,
                    peer_node_id=claiming_peer_id,
                    aes_key=aes_key,
                    epoch=epoch,
                    created_at=time.time(),
                )

                self._log(
                    action="RESUMPTION_SUCCESS",
                    target=claiming_peer_id,
                    details={
                        "original_session_id": original_session_id.hex(),
                        "new_session_id": new_session_id.hex(),
                        "epoch": epoch,
                    },
                )

                return new_session_id

            except Exception as exc:
                self._log(
                    action="RESUMPTION_FAILED",
                    target=claiming_peer_id,
                    details={"error": str(exc)},
                )
                return None

    def cleanup_stale_sessions(
        self,
        reassembly_timeout_seconds: float = MAX_REASSEMBLY_TIMEOUT,
        session_ttl_seconds: float = SESSION_RESUMPTION_TTL,
    ) -> int:
        """Evict expired sessions and timed-out in-flight reassembly buffers."""
        with self._lock:
            now = time.time()
            stale_cutoff = now - session_ttl_seconds
            reassembly_cutoff = now - reassembly_timeout_seconds

            stale_ids = [
                sid
                for sid, sess in self._sessions.items()
                if sess.created_at < stale_cutoff
            ]

            for sid in stale_ids:
                session = self._sessions.pop(sid)
                self._resumption_tickets.pop(sid, None)

                self._log(
                    action="SESSION_EXPIRED",
                    target=session.peer_node_id,
                    details={
                        "session_id": sid.hex(),
                        "age_seconds": now - session.created_at,
                    },
                )

            timed_out_count = 0
            for session in self._sessions.values():
                timed_out_msgs = [
                    msg_id
                    for msg_id, entry in session.in_flight.items()
                    if entry["received_at"] < reassembly_cutoff
                ]
                for msg_id in timed_out_msgs:
                    del session.in_flight[msg_id]
                    timed_out_count += 1

                    self._log(
                        action="REASSEMBLY_TIMEOUT",
                        target=session.peer_node_id,
                        details={
                            "session_id": session.session_id.hex(),
                            "msg_id": msg_id,
                        },
                    )

            return len(stale_ids) + timed_out_count
