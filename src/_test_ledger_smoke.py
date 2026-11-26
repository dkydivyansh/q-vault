"""Smoke test for ledger.py."""

import json
import os
import sys
import tempfile

sys.path.insert(0, "src")

from cryptography.hazmat.primitives.asymmetric import mldsa
from ledger import AuditLedger

priv = mldsa.MLDSA65PrivateKey.generate()
pub = priv.public_key()

with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    path = f.name

try:
    ledger = AuditLedger(path, priv, pub, checkpoint_interval=3)

    for i in range(5):
        e = ledger.log("alice", f"ACTION_{i}", f"resource_{i}", {"seq": i})
        print(
            f"Entry {e.entry_id}: hash={e.entry_hash[:16]}... cp={e.is_checkpoint} sig={bool(e.checkpoint_signature)}"
        )

    result = ledger.verify_chain()
    print(
        f"\nverify_chain ok={result['ok']} total={result['total_entries']} tampered={result['tampered_entries']} bad_cp={result['bad_checkpoints']}"
    )
    print(f"Message: {result['message']}")
    assert result["ok"], "Chain verification failed!"

    entries = ledger.get_entries(since_id=2, limit=3)
    print(
        f"\nget_entries(since_id=2, limit=3): got {len(entries)} entries, ids={[e.entry_id for e in entries]}"
    )
    assert len(entries) == 3
    assert entries[0].entry_id == 2

    summary = ledger.export_summary()
    print(f"\nexport_summary: {summary}")
    assert summary["total_entries"] == 5

    evil_actor = 'alice\n{"actor":"admin","action":"grant"}'
    e_evil = ledger.log(evil_actor, "TEST", "nothing", {})
    raw = open(path, encoding="utf-8").readlines()[-1]
    parsed = json.loads(raw)
    assert parsed["actor"] == evil_actor, "Actor field mismatch"
    print("\nInjection test PASSED — newline in actor stored safely, line is valid JSON")

    ledger2 = AuditLedger(path, priv, pub, checkpoint_interval=3)
    assert ledger2._entry_count == 6, f"Expected 6, got {ledger2._entry_count}"
    assert ledger2._prev_hash == e_evil.entry_hash
    print("Reload test PASSED — counters restored from disk correctly")

    print("\nALL TESTS PASSED")

finally:
    os.unlink(path)
