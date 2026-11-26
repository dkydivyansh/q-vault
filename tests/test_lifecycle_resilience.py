"""Key lifecycle, rotation, cross-node revocation, WAL crash recovery, and backup integrity tests."""

import os
import secrets
import sqlite3
import subprocess
import sys

import pytest

from src.sdk import (
    KeyAuthority,
    NodeGateway,
    PeerInfo,
    generate_identity_keypair,
    serialize_private_keys,
    serialize_public_keys,
)


def _register_gateway(auth: KeyAuthority, node_id: str) -> tuple[NodeGateway, PeerInfo]:
    kp = generate_identity_keypair(node_id)
    pub = serialize_public_keys(kp)
    priv = serialize_private_keys(kp)
    auth.register_node(
        node_id, pub["signing_public"], pub["kem_public"], pub["x25519_public"]
    )
    gw = NodeGateway(node_id, priv, authority_client=auth)
    peer = PeerInfo(node_id, pub["signing_public"], pub["kem_public"], pub["x25519_public"])
    return gw, peer


def test_epoch_rotation_grace_window_and_hard_cutoff(tmp_path):
    db_path = str(tmp_path / "auth.db")
    auth = KeyAuthority(db_path, secrets.token_hex(32), grace_period_seconds=30.0)

    rot1 = auth.rotate_keys()
    assert rot1.epoch == 1
    assert auth.is_epoch_valid(1, check_time=rot1.valid_from + 1.0) is True
    assert auth.is_epoch_valid(0, check_time=rot1.valid_from + 10.0) is True
    assert auth.is_epoch_valid(0, check_time=rot1.cutoff + 0.1) is False

    rot2 = auth.rotate_keys()
    assert rot2.epoch == 2
    assert auth.is_epoch_valid(1, check_time=rot2.valid_from + 5.0) is True
    assert auth.is_epoch_valid(1, check_time=rot2.cutoff + 0.1) is False
    assert auth.is_epoch_valid(0, check_time=rot2.valid_from + 1.0) is False
    auth.close()


def test_cross_node_revocation_propagation_and_re_enrollment(tmp_path):
    db_path = str(tmp_path / "auth.db")
    auth = KeyAuthority(db_path, secrets.token_hex(32), grace_period_seconds=30.0)

    gw_a, peer_a = _register_gateway(auth, "NodeA")
    gw_b, peer_b = _register_gateway(auth, "NodeB")
    gw_c, peer_c = _register_gateway(auth, "NodeC")

    for gw, peer in [(gw_a, peer_b), (gw_a, peer_c), (gw_b, peer_a), (gw_b, peer_c), (gw_c, peer_a), (gw_c, peer_b)]:
        gw.register_peer(peer)

    auth_pub = auth.get_authority_public_key_bytes()
    auth.register_revocation_callback(lambda notice: [g.apply_revocation(notice, auth_pub) for g in (gw_a, gw_b, gw_c)])

    notice = auth.revoke_node("NodeA", reason="compromised-device")
    stats = auth.get_propagation_stats(notice.revocation_epoch)
    assert auth.is_revoked("NodeA") is True
    assert auth.is_revoked("NodeB") is False
    assert stats["total_acked"] == 3
    assert stats["max_propagation_ms"] >= 0.0

    with pytest.raises(PermissionError):
        gw_b.initiate_handshake("NodeA", epoch=0)

    # Unaffected peers continue operating normally.
    ct, eph, sig, sid_b = gw_b.initiate_handshake("NodeC", epoch=0)
    sid_c = gw_c.complete_handshake("NodeB", ct, eph, sig, epoch=0)
    assert sid_b == sid_c

    # Owner re-enrolls under a fresh device identity while old key stays revoked.
    kp_v2 = generate_identity_keypair("NodeA_v2")
    pub_v2 = serialize_public_keys(kp_v2)
    rec = auth.re_enroll_node(
        "NodeA_v2",
        pub_v2["signing_public"],
        pub_v2["kem_public"],
        pub_v2["x25519_public"],
        previous_node_id="NodeA",
    )
    assert rec.is_revoked is False
    assert auth.is_revoked("NodeA") is True
    auth.close()


def test_backup_and_corrupt_backup_rejection(tmp_path):
    db_path = str(tmp_path / "auth.db")
    kek = secrets.token_hex(32)
    auth = KeyAuthority(db_path, kek)
    backup_file = str(tmp_path / "authority.qvbak")
    auth.backup_keys(backup_file)

    assert auth.restore_from_backup(backup_file) is True

    raw = bytearray(open(backup_file, "rb").read())
    raw[60] ^= 0x01
    corrupt_file = str(tmp_path / "corrupt.qvbak")
    open(corrupt_file, "wb").write(bytes(raw))

    with pytest.raises(ValueError):
        auth.restore_from_backup(corrupt_file)
    auth.close()


def test_wal_crash_recovery_preserves_committed_state_and_revocations(tmp_path):
    db_path = str(tmp_path / "crash.db")
    kek = secrets.token_hex(32)
    auth = KeyAuthority(db_path, kek)
    _, _ = _register_gateway(auth, "NodeA")
    _, _ = _register_gateway(auth, "NodeB")
    auth.rotate_keys()
    auth.revoke_node("NodeA", reason="pre-crash-revocation")
    auth.close()

    # Simulate abrupt process termination mid-rotation before COMMIT.
    crash_script = (
        "import os, sqlite3\n"
        f"conn = sqlite3.connect(r'{db_path}', isolation_level=None)\n"
        "conn.execute('PRAGMA journal_mode=WAL')\n"
        "conn.execute('BEGIN IMMEDIATE')\n"
        "conn.execute(\"INSERT INTO epochs (epoch, valid_from, grace_until, cutoff, signature) VALUES (99, 1.0, 2.0, 2.0, x'00')\")\n"
        "os._exit(1)\n"
    )
    proc = subprocess.run([sys.executable, "-c", crash_script], check=False)
    assert proc.returncode == 1

    recovered = KeyAuthority(db_path, kek)
    assert recovered.current_epoch == 1
    assert recovered.is_revoked("NodeA") is True
    assert recovered.is_revoked("NodeB") is False
    recovered.close()


def test_restart_persists_revocations_across_nodes_and_ledger_checkpoints(tmp_path):
    from src.app.config import load_config
    from src.app.runtime import SentinelRuntime

    cfg = load_config(
        db_path=str(tmp_path / "state.db"),
        ledger_path=str(tmp_path / "audit.jsonl"),
        backup_dir=str(tmp_path / "backups"),
        master_kek_hex=secrets.token_hex(32),
    )
    cfg.checkpoint_interval = 3

    rt1 = SentinelRuntime(cfg)
    rt1.provision_default_topology()
    rt1.send_encrypted_transfer("WebPortal", "Auth", b"pre-restart message")
    rt1.revoke_node("FileGateway", reason="compromise-before-restart")
    rt1.close()

    rt2 = SentinelRuntime(cfg)
    rt2.provision_default_topology()
    assert rt2.authority.is_revoked("FileGateway") is True
    with pytest.raises(PermissionError):
        rt2.send_encrypted_transfer("WebPortal", "FileGateway", b"blocked after restart")

    post_alerts = rt2.ingest_service_event(
        actor="FileGateway",
        action="SERVICE_CALL",
        source_service="FileGateway",
        target_service="VaultDB",
        flush_immediately=True,
    )
    assert any(a["violated_rule"] == "REVOKED_001" for a in post_alerts)

    verify_res = rt2.ledger.verify_chain()
    assert verify_res["ok"] is True
    assert verify_res["bad_checkpoints"] == []
    rt2.close()
