"""FastAPI application wrapper exposing a NodeGateway over HTTP endpoints."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.sdk import NodeGateway, PeerInfo, RevocationNotice


class HandshakeRequest(BaseModel):
    peer_node_id: str
    kem_ciphertext_hex: str
    ephemeral_x25519_pub_hex: str
    peer_signature_hex: str
    epoch: int


class ReceiveChunkRequest(BaseModel):
    session_id_hex: str
    nonce_hex: str
    ciphertext_hex: str
    aad_json: str
    seq_num: int


class ResumptionTicketRequest(BaseModel):
    session_id_hex: str


class ResumeSessionRequest(BaseModel):
    ticket_hex: str
    claiming_peer_id: str


class RevocationPushRequest(BaseModel):
    node_id: str
    revocation_epoch: int
    revoked_at: float
    reason: str
    signature_hex: str
    authority_public_key_hex: str


def create_service_node_app(
    gateway: NodeGateway, peer_info: PeerInfo | None = None
) -> FastAPI:
    """Create a FastAPI service endpoint protected by `gateway`."""
    app = FastAPI(title=f"Q-Vault Service Node ({gateway.node_id})")

    @app.get("/health")
    def health() -> dict:
        payload = {"status": "ok", "node_id": gateway.node_id}
        if peer_info is not None:
            payload["signing_public_hex"] = peer_info.signing_public_bytes.hex()
            payload["kem_public_hex"] = peer_info.kem_public_bytes.hex()
            payload["x25519_public_hex"] = peer_info.x25519_public_bytes.hex()
        return payload

    @app.post("/pqc/handshake")
    def handshake(req: HandshakeRequest) -> dict:
        try:
            session_id = gateway.complete_handshake(
                peer_node_id=req.peer_node_id,
                kem_ciphertext=bytes.fromhex(req.kem_ciphertext_hex),
                ephemeral_x25519_public_bytes=bytes.fromhex(req.ephemeral_x25519_pub_hex),
                peer_signature=bytes.fromhex(req.peer_signature_hex),
                epoch=req.epoch,
            )
            return {"session_id_hex": session_id.hex()}
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/pqc/receive")
    def receive_chunk(req: ReceiveChunkRequest) -> dict:
        plaintext = gateway.receive_chunk(
            session_id=bytes.fromhex(req.session_id_hex),
            nonce=bytes.fromhex(req.nonce_hex),
            ciphertext=bytes.fromhex(req.ciphertext_hex),
            aad_json=req.aad_json,
            seq_num=req.seq_num,
        )
        if plaintext is None:
            return {"status": "pending_or_rejected", "reassembled_hex": None}
        return {
            "status": "delivered",
            "reassembled_hex": plaintext.hex(),
            "bytes": len(plaintext),
        }

    @app.post("/pqc/ticket")
    def create_ticket(req: ResumptionTicketRequest) -> dict:
        try:
            ticket = gateway.create_resumption_ticket(
                session_id=bytes.fromhex(req.session_id_hex),
            )
            return {"ticket_hex": ticket.hex()}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/pqc/resume")
    def resume(req: ResumeSessionRequest) -> dict:
        new_sid = gateway.resume_session(
            ticket_bytes=bytes.fromhex(req.ticket_hex),
            claiming_peer_id=req.claiming_peer_id,
        )
        if new_sid is None:
            raise HTTPException(status_code=403, detail="Resumption rejected")
        return {"session_id_hex": new_sid.hex()}

    @app.post("/pqc/revocation")
    def apply_revocation(req: RevocationPushRequest) -> dict:
        notice = RevocationNotice(
            node_id=req.node_id,
            revocation_epoch=req.revocation_epoch,
            revoked_at=req.revoked_at,
            reason=req.reason,
            signature=bytes.fromhex(req.signature_hex),
        )
        ok = gateway.apply_revocation(
            notice, bytes.fromhex(req.authority_public_key_hex)
        )
        if not ok:
            raise HTTPException(status_code=400, detail="Invalid authority signature")
        return {"enforced": True, "node_id": req.node_id}

    return app
