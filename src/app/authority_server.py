"""FastAPI router for the Q-Vault Sentinel Key Authority, Audit Ledger, and Watchdog API."""

import time
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.sdk import LogEvent

from .runtime import SentinelRuntime


class RegisterNodeRequest(BaseModel):
    node_id: str
    signing_public_hex: str
    kem_public_hex: str
    x25519_public_hex: str


class RevokeRequest(BaseModel):
    node_id: str
    reason: str = "operator-triggered"


class TransferRequest(BaseModel):
    source_node: str
    target_node: str
    payload_text: str


class IngestEventRequest(BaseModel):
    actor: str
    action: str
    source_service: str
    target_service: str
    timestamp: Optional[float] = None
    flush_immediately: bool = True


class RestoreRequest(BaseModel):
    backup_path: str


def create_authority_router(runtime: SentinelRuntime) -> APIRouter:
    """Create FastAPI router exposing control plane, telemetry, and detector endpoints."""
    router = APIRouter(prefix="/api/v1")

    @router.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "epoch": runtime.authority.current_epoch,
            "revocation_epoch": runtime.authority.revocation_epoch,
        }

    @router.get("/status")
    def status() -> dict:
        return runtime.get_snapshot()

    @router.post("/authority/nodes/register")
    def register_node(req: RegisterNodeRequest) -> dict:
        try:
            rec = runtime.authority.register_node(
                node_id=req.node_id,
                signing_public_bytes=bytes.fromhex(req.signing_public_hex),
                kem_public_bytes=bytes.fromhex(req.kem_public_hex),
                x25519_public_bytes=bytes.fromhex(req.x25519_public_hex),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "node_id": rec.node_id,
            "key_epoch": rec.key_epoch,
            "registered_at": rec.registered_at,
        }

    @router.post("/authority/rotate")
    def rotate() -> dict:
        return runtime.rotate_epoch()

    @router.post("/authority/revoke")
    def revoke(req: RevokeRequest) -> dict:
        try:
            return runtime.revoke_node(req.node_id, reason=req.reason)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/authority/backup")
    def backup() -> dict:
        return runtime.backup_authority()

    @router.post("/authority/restore")
    def restore(req: RestoreRequest) -> dict:
        try:
            ok = runtime.authority.restore_from_backup(req.backup_path)
            return {"restored": ok}
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/gateway/transfer")
    def transfer(req: TransferRequest) -> dict:
        try:
            return runtime.send_encrypted_transfer(
                req.source_node, req.target_node, req.payload_text.encode("utf-8")
            )
        except (ValueError, PermissionError, RuntimeError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @router.get("/ledger/verify")
    def verify_ledger() -> dict:
        return runtime.ledger.verify_chain()

    @router.get("/ledger/entries")
    def ledger_entries(since_id: int = 0, limit: int = 50) -> dict:
        entries = runtime.ledger.get_entries(since_id=since_id, limit=limit)
        return {
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "timestamp": e.timestamp,
                    "actor": e.actor,
                    "action": e.action,
                    "target": e.target,
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                    "is_checkpoint": e.is_checkpoint,
                }
                for e in entries
            ]
        }

    @router.post("/detector/events")
    def ingest_event(req: IngestEventRequest) -> dict:
        alerts = runtime.ingest_service_event(
            actor=req.actor,
            action=req.action,
            source_service=req.source_service,
            target_service=req.target_service,
            timestamp=req.timestamp,
            flush_immediately=req.flush_immediately,
        )
        return {"alerts": alerts, "metrics": runtime.detector.get_metrics_report()}

    @router.post("/detector/flush")
    def flush_detector() -> dict:
        flushed = [runtime._serialize_alert(a) for a in runtime.detector.flush()]
        return {"alerts": flushed, "metrics": runtime.detector.get_metrics_report()}

    @router.get("/detector/alerts")
    def list_alerts() -> dict:
        return {"alerts": [runtime._serialize_alert(a) for a in runtime.detector.get_alerts()]}

    @router.get("/detector/metrics")
    def detector_metrics() -> dict:
        return runtime.detector.get_metrics_report()

    @router.get("/detector/graph")
    def service_graph() -> dict:
        return runtime.detector.get_service_graph_summary()

    @router.post("/scenarios/lateral-movement")
    def simulate_lateral_movement() -> dict:
        target_actor = "FileGateway"
        if target_actor not in runtime.gateways:
            runtime.register_service_node(target_actor)

        now = time.time() - 10.0
        steps = [
            ("WebPortal", "FileGateway", now),
            ("FileGateway", "VaultDB", now + 1.0),
            ("VaultDB", "PayrollDB", now + 2.0),
            ("PayrollDB", "Admin", now + 3.0),
        ]
        triggered: List[dict] = []
        for src, dst, ts in steps:
            triggered.extend(
                runtime.ingest_service_event(
                    actor=target_actor,
                    action="SERVICE_CALL",
                    source_service=src,
                    target_service=dst,
                    timestamp=ts,
                    flush_immediately=True,
                )
            )
        return {
            "actor": target_actor,
            "is_revoked": runtime.authority.is_revoked(target_actor),
            "alerts": triggered,
        }

    return router
