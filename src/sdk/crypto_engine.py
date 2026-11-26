"""
crypto_engine.py — Q-Vault Sentinel Core Cryptographic Engine

Post-quantum and classical cryptographic primitives built on pyca/cryptography:
ML-KEM-768, ML-DSA-65 (FIPS 204 hedged mode with context separation), X25519,
HKDF-SHA256, and AES-256-GCM.
"""

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CTX_HANDSHAKE = b"qvault-handshake-v1"
CTX_EPOCH = b"qvault-epoch-v1"
CTX_REVOKE = b"qvault-revoke-v1"
CTX_LOG = b"qvault-log-v1"
CTX_BACKUP = b"qvault-backup-v1"
CTX_RESUMPTION = b"qvault-resumption-v1"

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
HKDF_INFO = b"qvault-session-v1"

MLDSA65_PUBKEY_RAW_BYTES = 1952
MLKEM768_PUBKEY_RAW_BYTES = 1184
X25519_PUBKEY_RAW_BYTES = 32


@dataclass
class HybridKeyPair:
    """Segregated ML-DSA-65 signing and ML-KEM-768/X25519 key-establishment identity."""

    signing_private: mldsa.MLDSA65PrivateKey
    signing_public: mldsa.MLDSA65PublicKey
    kem_private: mlkem.MLKEM768PrivateKey
    kem_public: mlkem.MLKEM768PublicKey
    x25519_private: X25519PrivateKey
    node_id: str = ""


@dataclass
class SessionKeys:
    """Ephemeral symmetric session keys derived for a single protocol epoch."""

    session_id: bytes
    aes_key: bytes
    peer_id: str
    epoch: int
    created_at: float = field(default_factory=time.time)


@dataclass
class EncryptedChunk:
    """Authenticated AES-256-GCM message fragment with bound transport metadata."""

    msg_id: str
    chunk_idx: int
    total_chunks: int
    sender_id: str
    recipient_id: str
    key_epoch: int
    seq_num: int
    nonce: bytes
    ciphertext: bytes
    tag_included: bool = True


@dataclass
class HandshakeResult:
    """Result of an authenticated hybrid handshake."""

    session_keys: SessionKeys
    transcript_hash: bytes
    peer_node_id: str


def generate_identity_keypair(node_id: str) -> HybridKeyPair:
    """Generate a hybrid ML-DSA-65, ML-KEM-768, and X25519 identity keypair."""
    signing_private = mldsa.MLDSA65PrivateKey.generate()
    signing_public = signing_private.public_key()
    kem_private = mlkem.MLKEM768PrivateKey.generate()
    kem_public = kem_private.public_key()
    x25519_private = X25519PrivateKey.generate()

    return HybridKeyPair(
        signing_private=signing_private,
        signing_public=signing_public,
        kem_private=kem_private,
        kem_public=kem_public,
        x25519_private=x25519_private,
        node_id=node_id,
    )


def serialize_public_keys(keypair: HybridKeyPair) -> dict[str, bytes]:
    """Serialize public identity keys to raw bytes matching FIPS 203/204 sizes."""
    return {
        "signing_public": keypair.signing_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        "kem_public": keypair.kem_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        "x25519_public": keypair.x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    }


def serialize_private_keys(keypair: HybridKeyPair) -> dict[str, bytes]:
    """Serialize private identity keys for NodeGateway initialization."""
    return {
        "mldsa_private": keypair.signing_private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "mlkem_private": keypair.kem_private.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "x25519_private": keypair.x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    }


def load_mldsa_public_key(data: bytes) -> mldsa.MLDSA65PublicKey:
    """Load an ML-DSA-65 public key from raw (1952B) or DER SPKI bytes."""
    if len(data) == MLDSA65_PUBKEY_RAW_BYTES:
        return mldsa.MLDSA65PublicKey.from_public_bytes(data)
    loaded = serialization.load_der_public_key(data)
    if not isinstance(loaded, mldsa.MLDSA65PublicKey):
        raise ValueError("Expected ML-DSA-65 public key")
    return loaded


def load_mlkem_public_key(data: bytes) -> mlkem.MLKEM768PublicKey:
    """Load an ML-KEM-768 public key from raw (1184B) or DER SPKI bytes."""
    if len(data) == MLKEM768_PUBKEY_RAW_BYTES:
        return mlkem.MLKEM768PublicKey.from_public_bytes(data)
    loaded = serialization.load_der_public_key(data)
    if not isinstance(loaded, mlkem.MLKEM768PublicKey):
        raise ValueError("Expected ML-KEM-768 public key")
    return loaded


def perform_handshake_initiator(
    my_keypair: HybridKeyPair,
    peer_kem_public: mlkem.MLKEM768PublicKey,
    peer_signing_public: mldsa.MLDSA65PublicKey,
    peer_x25519_public_bytes: bytes,
    peer_node_id: str,
    epoch: int,
) -> tuple[HandshakeResult, bytes, bytes, bytes]:
    """Execute initiator side of hybrid handshake; returns (HandshakeResult, kem_ct, eph_pub, sig)."""
    ephemeral_x25519_private = X25519PrivateKey.generate()
    ephemeral_x25519_public_bytes = ephemeral_x25519_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    peer_x25519_pub = X25519PublicKey.from_public_bytes(peer_x25519_public_bytes)
    x25519_shared = ephemeral_x25519_private.exchange(peer_x25519_pub)
    # cryptography>=50 encapsulate() returns (shared_secret, ciphertext).
    kem_shared_secret, kem_ciphertext = peer_kem_public.encapsulate()

    combined_secret = x25519_shared + kem_shared_secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=None,
        info=HKDF_INFO,
    ).derive(combined_secret)

    session_id = hashlib.sha256(aes_key + peer_node_id.encode()).digest()[:16]
    transcript = json.dumps(
        {
            "initiator": my_keypair.node_id,
            "responder": peer_node_id,
            "epoch": epoch,
            "session_id": session_id.hex(),
        },
        sort_keys=True,
    ).encode()

    signature = my_keypair.signing_private.sign(transcript, context=CTX_HANDSHAKE)

    # Clear ephemeral secret reference immediately after key derivation (FIPS 204 §3.6.3).
    ephemeral_x25519_private = None  # noqa: F841

    transcript_hash = hashlib.sha256(transcript).digest()
    session_keys = SessionKeys(
        session_id=session_id,
        aes_key=aes_key,
        peer_id=peer_node_id,
        epoch=epoch,
    )
    handshake_result = HandshakeResult(
        session_keys=session_keys,
        transcript_hash=transcript_hash,
        peer_node_id=peer_node_id,
    )
    return (handshake_result, kem_ciphertext, ephemeral_x25519_public_bytes, signature)


def perform_handshake_responder(
    my_keypair: HybridKeyPair,
    kem_ciphertext: bytes,
    peer_x25519_ephemeral_bytes: bytes,
    peer_signing_public: mldsa.MLDSA65PublicKey,
    peer_node_id: str,
    peer_signature: bytes,
    epoch: int,
) -> HandshakeResult:
    """Execute responder side of hybrid handshake and verify initiator's transcript signature."""
    kem_shared_secret = my_keypair.kem_private.decapsulate(kem_ciphertext)
    peer_ephemeral_pub = X25519PublicKey.from_public_bytes(peer_x25519_ephemeral_bytes)
    x25519_shared = my_keypair.x25519_private.exchange(peer_ephemeral_pub)

    combined_secret = x25519_shared + kem_shared_secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=None,
        info=HKDF_INFO,
    ).derive(combined_secret)

    session_id = hashlib.sha256(aes_key + my_keypair.node_id.encode()).digest()[:16]
    transcript = json.dumps(
        {
            "initiator": peer_node_id,
            "responder": my_keypair.node_id,
            "epoch": epoch,
            "session_id": session_id.hex(),
        },
        sort_keys=True,
    ).encode()

    # Authenticate peer transcript before accepting derived session keys.
    try:
        peer_signing_public.verify(peer_signature, transcript, context=CTX_HANDSHAKE)
    except InvalidSignature:
        raise ValueError(
            f"Handshake signature verification failed for peer '{peer_node_id}': "
            "the peer did not prove knowledge of its private signing key, "
            "or the transcript was tampered with in transit."
        )

    transcript_hash = hashlib.sha256(transcript).digest()
    session_keys = SessionKeys(
        session_id=session_id,
        aes_key=aes_key,
        peer_id=peer_node_id,
        epoch=epoch,
    )
    return HandshakeResult(
        session_keys=session_keys,
        transcript_hash=transcript_hash,
        peer_node_id=peer_node_id,
    )


def encrypt_chunk(
    session_keys: SessionKeys,
    plaintext: bytes,
    msg_id: str,
    chunk_idx: int,
    total_chunks: int,
    seq_num: int,
    sender_id: str,
    recipient_id: str,
) -> EncryptedChunk:
    """Encrypt one chunk with AES-256-GCM and bind transport metadata into AAD."""
    aad = json.dumps(
        {
            "msg_id": msg_id,
            "chunk_idx": chunk_idx,
            "total_chunks": total_chunks,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "key_epoch": session_keys.epoch,
            "seq_num": seq_num,
        },
        sort_keys=True,
    ).encode()

    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(session_keys.aes_key).encrypt(nonce, plaintext, aad)

    return EncryptedChunk(
        msg_id=msg_id,
        chunk_idx=chunk_idx,
        total_chunks=total_chunks,
        sender_id=sender_id,
        recipient_id=recipient_id,
        key_epoch=session_keys.epoch,
        seq_num=seq_num,
        nonce=nonce,
        ciphertext=ciphertext,
        tag_included=True,
    )


def decrypt_chunk(
    session_keys: SessionKeys,
    chunk: EncryptedChunk,
    sender_id: str,
    recipient_id: str,
) -> bytes:
    """Decrypt an EncryptedChunk and verify bound metadata; raises InvalidTag on mismatch."""
    aad = json.dumps(
        {
            "msg_id": chunk.msg_id,
            "chunk_idx": chunk.chunk_idx,
            "total_chunks": chunk.total_chunks,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "key_epoch": session_keys.epoch,
            "seq_num": chunk.seq_num,
        },
        sort_keys=True,
    ).encode()

    return AESGCM(session_keys.aes_key).decrypt(chunk.nonce, chunk.ciphertext, aad)


def sign_data(
    private_key: mldsa.MLDSA65PrivateKey,
    data: bytes,
    ctx: bytes,
) -> bytes:
    """Sign data with ML-DSA-65 using a domain-separation context string."""
    return private_key.sign(data, context=ctx)


def verify_signature(
    public_key: mldsa.MLDSA65PublicKey,
    data: bytes,
    signature: bytes,
    ctx: bytes,
) -> bool:
    """Verify an ML-DSA-65 signature under the expected context; returns False on failure."""
    try:
        public_key.verify(signature, data, context=ctx)
        return True
    except InvalidSignature:
        return False


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM; returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext_with_tag


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify authentication tag."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def derive_key(
    secret: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """Derive a key from keying material using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(secret)


def sha256_hash(data: bytes) -> bytes:
    """Return raw 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def generate_session_resumption_ticket(
    session_keys: SessionKeys,
    signing_key: mldsa.MLDSA65PrivateKey,
    master_kek: bytes,
) -> bytes:
    """Issue an AES-256-GCM encrypted, ML-DSA-65 signed, peer-bound resumption ticket."""
    ticket_json = json.dumps(
        {
            "session_id": session_keys.session_id.hex(),
            "peer_id": session_keys.peer_id,
            "epoch": session_keys.epoch,
            "expiry": int(time.time()) + 3600,
        },
        sort_keys=True,
    ).encode()

    nonce, ciphertext = aes_gcm_encrypt(master_kek, ticket_json)
    # Sign ciphertext rather than plaintext so verification precedes decryption.
    signature = signing_key.sign(ciphertext, context=CTX_BACKUP)
    ciphertext_len = struct.pack(">I", len(ciphertext))
    return nonce + ciphertext_len + ciphertext + signature


def validate_resumption_ticket(
    ticket_bytes: bytes,
    verify_key: mldsa.MLDSA65PublicKey,
    master_kek: bytes,
    claiming_peer_id: str,
) -> Optional[dict]:
    """Verify signature, decrypt, and validate expiry and peer binding for a ticket."""
    try:
        nonce = ticket_bytes[:GCM_NONCE_BYTES]
        ciphertext_len = struct.unpack(
            ">I", ticket_bytes[GCM_NONCE_BYTES : GCM_NONCE_BYTES + 4]
        )[0]
        ciphertext_start = GCM_NONCE_BYTES + 4
        ciphertext_end = ciphertext_start + ciphertext_len
        ciphertext = ticket_bytes[ciphertext_start:ciphertext_end]
        signature = ticket_bytes[ciphertext_end:]

        # Verify before decrypting to avoid unauthenticated decryption side-channels.
        try:
            verify_key.verify(signature, ciphertext, context=CTX_BACKUP)
        except InvalidSignature:
            return None

        try:
            ticket_json = aes_gcm_decrypt(master_kek, nonce, ciphertext)
        except InvalidTag:
            return None

        ticket_dict = json.loads(ticket_json.decode())

        if ticket_dict.get("expiry", 0) <= time.time():
            return None

        if ticket_dict.get("peer_id") != claiming_peer_id:
            return None

        return ticket_dict
    except Exception:
        return None
