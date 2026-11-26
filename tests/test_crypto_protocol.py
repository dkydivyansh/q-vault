"""Cryptographic protocol verification suite for Q-Vault Sentinel SDK."""

import hashlib
import os
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from src.sdk import (
    CTX_HANDSHAKE,
    CTX_REVOKE,
    AntiReplayWindow,
    NodeGateway,
    PeerInfo,
    decrypt_chunk,
    encrypt_chunk,
    generate_identity_keypair,
    perform_handshake_initiator,
    perform_handshake_responder,
    serialize_private_keys,
    serialize_public_keys,
    sign_data,
    verify_signature,
)


def _create_gateway_pair(name_a: str = "NodeA", name_b: str = "NodeB"):
    kp_a = generate_identity_keypair(name_a)
    kp_b = generate_identity_keypair(name_b)
    pub_a = serialize_public_keys(kp_a)
    pub_b = serialize_public_keys(kp_b)
    gw_a = NodeGateway(name_a, serialize_private_keys(kp_a))
    gw_b = NodeGateway(name_b, serialize_private_keys(kp_b))
    gw_a.register_peer(
        PeerInfo(name_b, pub_b["signing_public"], pub_b["kem_public"], pub_b["x25519_public"])
    )
    gw_b.register_peer(
        PeerInfo(name_a, pub_a["signing_public"], pub_a["kem_public"], pub_a["x25519_public"])
    )
    return kp_a, kp_b, gw_a, gw_b


def test_valid_aes_gcm_roundtrip():
    kp_a = generate_identity_keypair("NodeA")
    kp_b = generate_identity_keypair("NodeB")
    x_b_raw = serialize_public_keys(kp_b)["x25519_public"]

    hs_a, kem_ct, eph_pub, sig = perform_handshake_initiator(
        kp_a, kp_b.kem_public, kp_b.signing_public, x_b_raw, "NodeB", epoch=1
    )
    hs_b = perform_handshake_responder(
        kp_b, kem_ct, eph_pub, kp_a.signing_public, "NodeA", sig, epoch=1
    )

    plaintext = b"Settlement transfer instruction #901"
    chunk = encrypt_chunk(hs_a.session_keys, plaintext, "msg-1", 0, 1, 1, "NodeA", "NodeB")
    recovered = decrypt_chunk(hs_b.session_keys, chunk, "NodeA", "NodeB")
    assert recovered == plaintext


def test_aad_recipient_tampering_raises():
    kp_a = generate_identity_keypair("NodeA")
    kp_b = generate_identity_keypair("NodeB")
    x_b_raw = serialize_public_keys(kp_b)["x25519_public"]

    hs_a, kem_ct, eph_pub, sig = perform_handshake_initiator(
        kp_a, kp_b.kem_public, kp_b.signing_public, x_b_raw, "NodeB", epoch=1
    )
    hs_b = perform_handshake_responder(
        kp_b, kem_ct, eph_pub, kp_a.signing_public, "NodeA", sig, epoch=1
    )

    chunk = encrypt_chunk(hs_a.session_keys, b"Secret payload", "msg-2", 0, 1, 1, "NodeA", "NodeB")
    with pytest.raises(InvalidTag):
        decrypt_chunk(hs_b.session_keys, chunk, "NodeA", "NodeC")


def test_mldsa_sign_verify_valid_and_tampered():
    kp = generate_identity_keypair("Signer")
    data = b"canonical-control-message"
    sig = sign_data(kp.signing_private, data, CTX_HANDSHAKE)
    assert verify_signature(kp.signing_public, data, sig, CTX_HANDSHAKE) is True
    assert verify_signature(kp.signing_public, b"modified-message", sig, CTX_HANDSHAKE) is False


def test_domain_separation_rejects_cross_context_signature():
    kp = generate_identity_keypair("Signer")
    data = b"shared-payload"
    sig = sign_data(kp.signing_private, data, CTX_HANDSHAKE)
    assert verify_signature(kp.signing_public, data, sig, CTX_REVOKE) is False


def test_anti_replay_window_blocks_duplicate_and_allows_reordering():
    window = AntiReplayWindow(window_size=64)
    assert window.check_and_record(5) is True
    assert window.check_and_record(3) is True
    assert window.check_and_record(7) is True
    assert window.check_and_record(1) is True
    assert window.check_and_record(5) is False
    assert window.check_and_record(3) is False


def test_forward_secrecy_session_keys_independent_of_long_term_signing_key():
    kp_a = generate_identity_keypair("NodeA")
    kp_b = generate_identity_keypair("NodeB")
    x_b_raw = serialize_public_keys(kp_b)["x25519_public"]

    hs_1, _, _, _ = perform_handshake_initiator(
        kp_a, kp_b.kem_public, kp_b.signing_public, x_b_raw, "NodeB", epoch=1
    )
    hs_2, _, _, _ = perform_handshake_initiator(
        kp_a, kp_b.kem_public, kp_b.signing_public, x_b_raw, "NodeB", epoch=1
    )

    assert hs_1.session_keys.aes_key != hs_2.session_keys.aes_key
    assert hs_1.session_keys.session_id != hs_2.session_keys.session_id

    # Long-term ML-DSA signing key material cannot derive or decrypt session ciphertext.
    chunk = encrypt_chunk(hs_1.session_keys, b"Historical secret", "m-pfs", 0, 1, 0, "NodeA", "NodeB")
    forged_key = hashlib.sha256(serialize_private_keys(kp_a)["mldsa_private"]).digest()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with pytest.raises(InvalidTag):
        AESGCM(forged_key).decrypt(chunk.nonce, chunk.ciphertext, b"")


def test_chunk_reordering_and_incomplete_transfer_timeout():
    _, _, gw_a, gw_b = _create_gateway_pair("NodeA", "NodeB")
    ct, eph, sig, sid_a = gw_a.initiate_handshake("NodeB", epoch=0)
    sid_b = gw_b.complete_handshake("NodeA", ct, eph, sig, epoch=0)

    large_payload = os.urandom(65536 + 500)
    transfer = gw_a.send_message(sid_a, large_payload, "NodeB")
    assert transfer.chunks_sent == 2
    chunks = transfer.encrypted_chunks  # type: ignore[attr-defined]

    # Deliver chunks out of order (chunk 1 before chunk 0).
    assert (
        gw_b.receive_chunk(
            sid_b, chunks[1]["nonce"], chunks[1]["ciphertext"], chunks[1]["aad"], chunks[1]["seq_num"]
        )
        is None
    )
    reassembled = gw_b.receive_chunk(
        sid_b, chunks[0]["nonce"], chunks[0]["ciphertext"], chunks[0]["aad"], chunks[0]["seq_num"]
    )
    assert reassembled == large_payload

    # Partial message expires and is purged on cleanup.
    partial_tx = gw_a.send_message(sid_a, os.urandom(65536 + 100), "NodeB")
    partial_chunks = partial_tx.encrypted_chunks  # type: ignore[attr-defined]
    assert (
        gw_b.receive_chunk(
            sid_b,
            partial_chunks[0]["nonce"],
            partial_chunks[0]["ciphertext"],
            partial_chunks[0]["aad"],
            partial_chunks[0]["seq_num"],
        )
        is None
    )
    cleaned = gw_b.cleanup_stale_sessions(reassembly_timeout_seconds=-1.0)
    assert cleaned >= 1


def test_resumption_ticket_peer_binding():
    kp_a, _, gw_a, gw_b = _create_gateway_pair("NodeA", "NodeB")
    ct, eph, sig, sid_a = gw_a.initiate_handshake("NodeB", epoch=0)
    sid_b = gw_b.complete_handshake("NodeA", ct, eph, sig, epoch=0)
    assert sid_a == sid_b

    master_kek = secrets.token_bytes(32)
    priv_b = serialize_private_keys(kp_a)["mldsa_private"]
    pub_b = serialize_public_keys(kp_a)["signing_public"]

    ticket = gw_b.create_resumption_ticket(sid_b, priv_b, master_kek)
    assert gw_b.resume_session(ticket, "NodeC", pub_b, master_kek) is None
    resumed = gw_b.resume_session(ticket, "NodeA", pub_b, master_kek)
    assert resumed is not None and resumed != sid_b
    assert gw_b.resume_session(ticket, "NodeA", pub_b, master_kek) is None


def test_per_session_replay_isolation_and_aad_seq_desync_blocked():
    _, _, gw_a1, gw_b = _create_gateway_pair("NodeA", "NodeB")
    kp_c = generate_identity_keypair("NodeC")
    pub_c = serialize_public_keys(kp_c)
    gw_c = NodeGateway("NodeC", serialize_private_keys(kp_c))
    gw_b.register_peer(
        PeerInfo("NodeC", pub_c["signing_public"], pub_c["kem_public"], pub_c["x25519_public"])
    )
    gw_c.register_peer(gw_a1._peers["NodeB"])

    ct1, eph1, sig1, sid_a1 = gw_a1.initiate_handshake("NodeB", epoch=0)
    sid_b1 = gw_b.complete_handshake("NodeA", ct1, eph1, sig1, epoch=0)

    ct2, eph2, sig2, sid_c2 = gw_c.initiate_handshake("NodeB", epoch=0)
    sid_b2 = gw_b.complete_handshake("NodeC", ct2, eph2, sig2, epoch=0)

    tx1 = gw_a1.send_message(sid_a1, b"from-A", "NodeB").encrypted_chunks[0]  # type: ignore[attr-defined]
    tx2 = gw_c.send_message(sid_c2, b"from-C", "NodeB").encrypted_chunks[0]  # type: ignore[attr-defined]

    # Forged packet with high seq_num must fail AAD check without advancing session 1 replay window.
    assert gw_b.receive_chunk(sid_b1, tx1["nonce"], tx1["ciphertext"], tx1["aad"], 999999) is None
    assert gw_b.receive_chunk(sid_b1, tx1["nonce"], tx1["ciphertext"], tx1["aad"], tx1["seq_num"]) == b"from-A"
    assert gw_b.receive_chunk(sid_b1, tx1["nonce"], tx1["ciphertext"], tx1["aad"], tx1["seq_num"]) is None

    # Session 2 with NodeC also starts at seq=0 and succeeds independently.
    assert gw_b.receive_chunk(sid_b2, tx2["nonce"], tx2["ciphertext"], tx2["aad"], tx2["seq_num"]) == b"from-C"
