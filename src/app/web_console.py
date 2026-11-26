"""FastAPI Web Console server exposing the control-plane API, service-node mounts, and UI."""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from src.sdk import PeerInfo, serialize_public_keys

from .authority_server import create_authority_router
from .config import SentinelConfig, load_config
from .runtime import SentinelRuntime
from .service_node import create_service_node_app

STATIC_INDEX = Path(__file__).parent / "static" / "index.html"


def create_web_console_app(
    runtime: Optional[SentinelRuntime] = None,
    config: Optional[SentinelConfig] = None,
) -> FastAPI:
    """Build the unified FastAPI application serving API, service nodes, and web console."""
    cfg = config or load_config()
    rt = runtime or SentinelRuntime(cfg)
    if not rt.gateways:
        rt.provision_default_topology()

    app = FastAPI(title="Q-Vault Sentinel Control Plane & Web Console")
    app.state.runtime = rt
    app.include_router(create_authority_router(rt))

    for node_id, gw in rt.gateways.items():
        pub = serialize_public_keys(rt.keypairs[node_id])
        peer_info = PeerInfo(
            node_id=node_id,
            signing_public_bytes=pub["signing_public"],
            kem_public_bytes=pub["kem_public"],
            x25519_public_bytes=pub["x25519_public"],
        )
        app.mount(f"/nodes/{node_id}", create_service_node_app(gw, peer_info))

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(STATIC_INDEX.read_text(encoding="utf-8"))

    return app
