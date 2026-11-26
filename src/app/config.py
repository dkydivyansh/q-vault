"""Runtime configuration loader for Q-Vault Sentinel applications."""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

DEFAULT_ALLOWED_PATHS: List[List[str]] = [
    ["WebPortal", "Auth"],
    ["WebPortal", "FileGateway"],
    ["Auth", "Billing"],
    ["Auth", "UserDB"],
    ["FileGateway", "VaultDB"],
    ["Billing", "PayrollDB"],
    ["Admin", "Auth"],
    ["Admin", "UserDB"],
    ["Admin", "VaultDB"],
    ["Admin", "Billing"],
    ["Admin", "PayrollDB"],
]


@dataclass
class SentinelConfig:
    """Typed application settings loaded from YAML policy and environment variables."""

    db_path: str
    ledger_path: str
    backup_dir: str
    master_kek_hex: str
    grace_period_seconds: float = 30.0
    clock_tolerance_seconds: float = 5.0
    lateral_window_seconds: float = 60.0
    lateral_max_hops: int = 3
    critical_severity_threshold: float = 0.85
    checkpoint_interval: int = 100
    allowed_paths: List[List[str]] = field(default_factory=lambda: [list(p) for p in DEFAULT_ALLOWED_PATHS])
    host: str = "127.0.0.1"
    port: int = 8700


def load_policy(policy_path: str = "config/policy.yaml") -> Dict[str, Any]:
    """Load YAML policy configuration if present, returning an empty mapping otherwise."""
    path = Path(policy_path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def load_config(
    policy_path: str = "config/policy.yaml",
    db_path: str | None = None,
    ledger_path: str | None = None,
    backup_dir: str | None = None,
    master_kek_hex: str | None = None,
) -> SentinelConfig:
    """Resolve runtime configuration from policy file and environment variables."""
    policy = load_policy(os.environ.get("QVAULT_POLICY_PATH", policy_path))
    rotation = policy.get("rotation", {})
    clock_skew = policy.get("clock_skew", {})
    service_graph = policy.get("service_graph", {})
    detection = policy.get("detection", {})
    ledger_cfg = policy.get("ledger", {})

    resolved_db = db_path or os.environ.get("QVAULT_DB_PATH", "./data/authority.db")
    resolved_ledger = ledger_path or os.environ.get("QVAULT_LEDGER_PATH", "./data/audit.jsonl")
    resolved_backups = backup_dir or os.environ.get("QVAULT_BACKUP_PATH", "./data/backups/")
    resolved_kek = master_kek_hex or os.environ.get("QVAULT_MASTER_KEK", "")

    if not resolved_kek or resolved_kek == "your-32-byte-hex-master-key-encryption-key-here":
        resolved_kek = secrets.token_hex(32)

    return SentinelConfig(
        db_path=resolved_db,
        ledger_path=resolved_ledger,
        backup_dir=resolved_backups,
        master_kek_hex=resolved_kek,
        grace_period_seconds=float(rotation.get("grace_period_seconds", 30.0)),
        clock_tolerance_seconds=float(clock_skew.get("tolerance_seconds", 5.0)),
        lateral_window_seconds=float(service_graph.get("lateral_movement_window_seconds", 60.0)),
        lateral_max_hops=int(service_graph.get("lateral_movement_max_hops", 3)),
        critical_severity_threshold=float(detection.get("critical_severity_threshold", 0.85)),
        checkpoint_interval=int(ledger_cfg.get("checkpoint_interval", 100)),
        allowed_paths=list(service_graph.get("allowed_paths", DEFAULT_ALLOWED_PATHS)),
        host=os.environ.get("QVAULT_AUTHORITY_HOST", "127.0.0.1"),
        port=int(os.environ.get("QVAULT_AUTHORITY_PORT", "8700")),
    )
