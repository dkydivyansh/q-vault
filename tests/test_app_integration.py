"""End-to-end FastAPI HTTP application and Web Console integration tests."""

import secrets

from fastapi.testclient import TestClient

from src.app.config import load_config
from src.app.runtime import SentinelRuntime
from src.app.web_console import create_web_console_app


def _make_test_client(tmp_path):
    cfg = load_config(
        db_path=str(tmp_path / "app.db"),
        ledger_path=str(tmp_path / "audit.jsonl"),
        backup_dir=str(tmp_path / "backups"),
        master_kek_hex=secrets.token_hex(32),
    )
    runtime = SentinelRuntime(cfg)
    app = create_web_console_app(runtime=runtime, config=cfg)
    return TestClient(app), runtime


def test_web_console_and_status_endpoints(tmp_path):
    client, runtime = _make_test_client(tmp_path)
    html_res = client.get("/")
    assert html_res.status_code == 200
    assert "Q-Vault Sentinel Control Plane" in html_res.text

    status_res = client.get("/api/v1/status")
    assert status_res.status_code == 200
    payload = status_res.json()
    assert len(payload["nodes"]) == 8
    assert payload["current_epoch"] == 0
    runtime.close()


def test_http_service_node_handshake_transfer_and_replay_rejection(tmp_path):
    client, runtime = _make_test_client(tmp_path)
    gw_portal = runtime.gateways["WebPortal"]

    ct, eph_pub, sig, sid = gw_portal.initiate_handshake("Auth", epoch=0)
    hs_res = client.post(
        "/nodes/Auth/pqc/handshake",
        json={
            "peer_node_id": "WebPortal",
            "kem_ciphertext_hex": ct.hex(),
            "ephemeral_x25519_pub_hex": eph_pub.hex(),
            "peer_signature_hex": sig.hex(),
            "epoch": 0,
        },
    )
    assert hs_res.status_code == 200
    assert hs_res.json()["session_id_hex"] == sid.hex()

    msg = b"Protected HTTP service payload"
    tx = gw_portal.send_message(sid, msg, "Auth")
    chunk = tx.encrypted_chunks[0]  # type: ignore[attr-defined]

    recv_res = client.post(
        "/nodes/Auth/pqc/receive",
        json={
            "session_id_hex": sid.hex(),
            "nonce_hex": chunk["nonce"].hex(),
            "ciphertext_hex": chunk["ciphertext"].hex(),
            "aad_json": chunk["aad"],
            "seq_num": chunk["seq_num"],
        },
    )
    assert recv_res.status_code == 200
    assert recv_res.json()["status"] == "delivered"
    assert bytes.fromhex(recv_res.json()["reassembled_hex"]) == msg

    replay_res = client.post(
        "/nodes/Auth/pqc/receive",
        json={
            "session_id_hex": sid.hex(),
            "nonce_hex": chunk["nonce"].hex(),
            "ciphertext_hex": chunk["ciphertext"].hex(),
            "aad_json": chunk["aad"],
            "seq_num": chunk["seq_num"],
        },
    )
    assert replay_res.status_code == 200
    assert replay_res.json()["status"] == "pending_or_rejected"
    runtime.close()


def test_http_lateral_movement_triggers_auto_revocation_and_ledger_verifies(tmp_path):
    client, runtime = _make_test_client(tmp_path)

    scenario_res = client.post("/api/v1/scenarios/lateral-movement")
    assert scenario_res.status_code == 200
    body = scenario_res.json()
    assert body["actor"] == "FileGateway"
    assert body["is_revoked"] is True

    blocked_tx = client.post(
        "/api/v1/gateway/transfer",
        json={
            "source_node": "FileGateway",
            "target_node": "VaultDB",
            "payload_text": "Attempted post-revocation access",
        },
    )
    assert blocked_tx.status_code == 403

    allowed_tx = client.post(
        "/api/v1/gateway/transfer",
        json={
            "source_node": "WebPortal",
            "target_node": "Auth",
            "payload_text": "Legitimate unaffected service call",
        },
    )
    assert allowed_tx.status_code == 200
    assert allowed_tx.json()["verified_match"] is True

    verify_res = client.get("/api/v1/ledger/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["ok"] is True
    runtime.close()


def test_http_service_node_resumption_hijack_blocked(tmp_path):
    client, runtime = _make_test_client(tmp_path)
    gw_portal = runtime.gateways["WebPortal"]
    ct, eph_pub, sig, sid = gw_portal.initiate_handshake("Auth", epoch=0)
    hs_res = client.post(
        "/nodes/Auth/pqc/handshake",
        json={
            "peer_node_id": "WebPortal",
            "kem_ciphertext_hex": ct.hex(),
            "ephemeral_x25519_pub_hex": eph_pub.hex(),
            "peer_signature_hex": sig.hex(),
            "epoch": 0,
        },
    )
    assert hs_res.status_code == 200

    ticket_res = client.post(
        "/nodes/Auth/pqc/ticket",
        json={"session_id_hex": sid.hex()},
    )
    assert ticket_res.status_code == 200
    ticket_hex = ticket_res.json()["ticket_hex"]

    hijack_res = client.post(
        "/nodes/Auth/pqc/resume",
        json={
            "ticket_hex": ticket_hex,
            "claiming_peer_id": "PayrollDB",
        },
    )
    assert hijack_res.status_code == 403

    valid_res = client.post(
        "/nodes/Auth/pqc/resume",
        json={
            "ticket_hex": ticket_hex,
            "claiming_peer_id": "WebPortal",
        },
    )
    assert valid_res.status_code == 200
    assert valid_res.json()["session_id_hex"]

    replay_ticket_res = client.post(
        "/nodes/Auth/pqc/resume",
        json={
            "ticket_hex": ticket_hex,
            "claiming_peer_id": "WebPortal",
        },
    )
    assert replay_ticket_res.status_code == 403
    runtime.close()
