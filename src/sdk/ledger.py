"""
ledger.py — Q-Vault Sentinel Tamper-Evident Audit Ledger

Append-only, SHA-256 hash-chained audit ledger using canonical single-line JSON
serialization and ML-DSA-65 signed checkpoints.
"""

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, List, Optional

from cryptography.hazmat.primitives.asymmetric import mldsa

from .crypto_engine import CTX_LOG

GENESIS_HASH = "0" * 64
DEFAULT_CHECKPOINT_INTERVAL = 100
_DSA_CONTEXT = CTX_LOG


@dataclass
class LogEntry:
    """Immutable audit record stored as a single canonical JSON line."""

    entry_id: int
    timestamp: float
    actor: str
    action: str
    target: str
    details: dict
    prev_hash: str
    entry_hash: str
    is_checkpoint: bool = False
    checkpoint_signature: Optional[str] = None


class AuditLedger:
    """Thread-safe, append-only, hash-chained audit ledger with ML-DSA-65 checkpoints."""

    def __init__(
        self,
        ledger_path: str,
        signing_key: mldsa.MLDSA65PrivateKey,
        verify_key: mldsa.MLDSA65PublicKey,
        checkpoint_interval: int = DEFAULT_CHECKPOINT_INTERVAL,
    ) -> None:
        self._ledger_path = Path(ledger_path)
        self._signing_key = signing_key
        self._verify_key = verify_key
        self._checkpoint_interval = max(1, checkpoint_interval)

        self._lock = threading.Lock()
        self._entry_count: int = 0
        self._prev_hash: str = GENESIS_HASH
        self._sinks: List[Callable[[LogEntry], None]] = []

        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_tail()

    def register_sink(self, callback: Callable[[LogEntry], None]) -> None:
        """Register a listener invoked after each entry is durably committed."""
        with self._lock:
            self._sinks.append(callback)

    def _load_tail(self) -> None:
        if not self._ledger_path.exists():
            return

        last_valid: Optional[dict] = None
        try:
            with self._ledger_path.open("r", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        entry_dict = json.loads(line)
                        if (
                            isinstance(entry_dict, dict)
                            and "entry_id" in entry_dict
                            and "entry_hash" in entry_dict
                        ):
                            last_valid = entry_dict
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return

        if last_valid is not None:
            self._entry_count = int(last_valid["entry_id"]) + 1
            self._prev_hash = str(last_valid["entry_hash"])

    def _canonical_json(self, data: dict) -> str:
        # sort_keys + ensure_ascii escapes control chars (\n, \r, \t) and keeps hashes reproducible.
        return json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )

    def _compute_entry_hash(self, prev_hash: str, canonical_entry_json: str) -> str:
        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("ascii"))
        hasher.update(canonical_entry_json.encode("utf-8"))
        return hasher.hexdigest()

    def log(
        self,
        actor: str,
        action: str,
        target: str,
        details: dict = None,
    ) -> LogEntry:
        """Append a canonicalized, hash-chained audit record and persist with fsync."""
        with self._lock:
            safe_details: dict = details if isinstance(details, dict) else {}

            # Must be decided prior to hashing so verify_chain() reconstructs the exact partial dict.
            is_checkpoint = (
                self._entry_count > 0
                and self._entry_count % self._checkpoint_interval == 0
            )

            partial: dict = {
                "entry_id": self._entry_count,
                "timestamp": time.time(),
                "actor": actor,
                "action": action,
                "target": target,
                "details": safe_details,
                "prev_hash": self._prev_hash,
                "is_checkpoint": is_checkpoint,
            }

            partial_json = self._canonical_json(partial)
            entry_hash = self._compute_entry_hash(self._prev_hash, partial_json)

            checkpoint_sig_hex: Optional[str] = None
            if is_checkpoint:
                raw_sig: bytes = self._signing_key.sign(
                    entry_hash.encode("ascii"),
                    context=_DSA_CONTEXT,
                )
                checkpoint_sig_hex = raw_sig.hex()

            entry = LogEntry(
                entry_id=self._entry_count,
                timestamp=partial["timestamp"],
                actor=actor,
                action=action,
                target=target,
                details=safe_details,
                prev_hash=self._prev_hash,
                entry_hash=entry_hash,
                is_checkpoint=is_checkpoint,
                checkpoint_signature=checkpoint_sig_hex,
            )

            # Append + fsync preserves existing file handles for concurrent readers on Windows/POSIX.
            final_json = self._canonical_json(asdict(entry))
            line = final_json + "\n"

            with self._ledger_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())

            self._prev_hash = entry_hash
            self._entry_count += 1
            sinks = list(self._sinks)

        for sink in sinks:
            try:
                sink(entry)
            except Exception:
                pass

        return entry

    def verify_chain(self) -> dict:
        """Verify SHA-256 hash linkage and ML-DSA-65 checkpoint signatures across the ledger."""
        tampered: List[int] = []
        bad_checkpoints: List[int] = []
        total = 0

        if not self._ledger_path.exists():
            return {
                "ok": True,
                "total_entries": 0,
                "tampered_entries": [],
                "bad_checkpoints": [],
                "message": "Ledger file does not exist — no entries to verify.",
            }

        expected_prev_hash = GENESIS_HASH

        try:
            with self._ledger_path.open("r", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        entry_dict = json.loads(line)
                    except json.JSONDecodeError:
                        tampered.append(-1)
                        continue

                    total += 1
                    eid = entry_dict.get("entry_id", -1)
                    stored_hash: str = entry_dict.get("entry_hash", "")
                    stored_prev: str = entry_dict.get("prev_hash", "")
                    is_cp: bool = entry_dict.get("is_checkpoint", False)
                    sig_hex: Optional[str] = entry_dict.get("checkpoint_signature")

                    partial_for_hash: dict = {
                        "entry_id": entry_dict.get("entry_id"),
                        "timestamp": entry_dict.get("timestamp"),
                        "actor": entry_dict.get("actor"),
                        "action": entry_dict.get("action"),
                        "target": entry_dict.get("target"),
                        "details": entry_dict.get("details", {}),
                        "prev_hash": stored_prev,
                        "is_checkpoint": is_cp,
                    }
                    partial_json = self._canonical_json(partial_for_hash)
                    expected_hash = self._compute_entry_hash(expected_prev_hash, partial_json)

                    if expected_hash != stored_hash:
                        tampered.append(eid)
                    # Advance with stored_hash so independent downstream edits remain detectable.
                    expected_prev_hash = stored_hash

                    if is_cp:
                        if not sig_hex:
                            bad_checkpoints.append(eid)
                        else:
                            try:
                                raw_sig = bytes.fromhex(sig_hex)
                                self._verify_key.verify(
                                    raw_sig,
                                    stored_hash.encode("ascii"),
                                    context=_DSA_CONTEXT,
                                )
                            except Exception:
                                bad_checkpoints.append(eid)

        except OSError as exc:
            return {
                "ok": False,
                "total_entries": total,
                "tampered_entries": tampered,
                "bad_checkpoints": bad_checkpoints,
                "message": f"Could not read ledger file: {exc}",
            }

        ok = not tampered and not bad_checkpoints
        if ok:
            msg = f"Chain intact. {total} entries verified, all signatures valid."
        else:
            parts = []
            if tampered:
                parts.append(f"{len(tampered)} tampered entry/entries: {tampered}")
            if bad_checkpoints:
                parts.append(f"{len(bad_checkpoints)} bad checkpoint(s): {bad_checkpoints}")
            msg = "INTEGRITY FAILURE — " + "; ".join(parts)

        return {
            "ok": ok,
            "total_entries": total,
            "tampered_entries": tampered,
            "bad_checkpoints": bad_checkpoints,
            "message": msg,
        }

    def get_entries(self, since_id: int = 0, limit: int = 100) -> List[LogEntry]:
        """Return up to `limit` entries with entry_id >= `since_id`."""
        results: List[LogEntry] = []

        if not self._ledger_path.exists():
            return results

        try:
            with self._ledger_path.open("r", encoding="utf-8") as fh:
                for raw_line in fh:
                    if len(results) >= limit:
                        break

                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if not isinstance(d, dict):
                        continue

                    eid = d.get("entry_id", -1)
                    if eid < since_id:
                        continue

                    try:
                        entry = LogEntry(
                            entry_id=int(d["entry_id"]),
                            timestamp=float(d["timestamp"]),
                            actor=str(d["actor"]),
                            action=str(d["action"]),
                            target=str(d["target"]),
                            details=dict(d.get("details", {})),
                            prev_hash=str(d["prev_hash"]),
                            entry_hash=str(d["entry_hash"]),
                            is_checkpoint=bool(d.get("is_checkpoint", False)),
                            checkpoint_signature=d.get("checkpoint_signature"),
                        )
                        results.append(entry)
                    except (KeyError, TypeError, ValueError):
                        continue
        except OSError:
            pass

        return results

    def export_summary(self) -> dict:
        """Return summary metadata of the ledger's committed state."""
        return {
            "total_entries": self._entry_count,
            "current_chain_head": self._prev_hash,
            "ledger_path": str(self._ledger_path),
        }
