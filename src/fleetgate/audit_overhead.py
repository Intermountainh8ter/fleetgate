"""Deterministic audit-log cost per entry at fleet-scale entry counts.

Counts serialized bytes, SHA-256 operations on append, checkpoints and SHA-256 operations in ``verify_full`` for logs
of 1,000 / 10,000 / 100,000 entries, and checks the chain verifies at every scale. Wall time appears only in
provenance. Simulated data only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import audit
from .audit import AuditLog

SCALES = (1_000, 10_000, 100_000)


class _CountingHashlib:
    """Stand-in for the ``hashlib`` name inside ``fleetgate.audit`` that counts sha256 calls."""

    def __init__(self) -> None:
        self.calls = 0

    def sha256(self, *a, **k):
        self.calls += 1
        return hashlib.sha256(*a, **k)


def _measure(n: int, seed: int) -> dict:
    rng = random.Random(seed * 1_000_003 + n)
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        log = AuditLog(checkpoint_every=32)
        for _ in range(n):
            log.append("collusion_verdict", arm="atomic_gate", agent=rng.randrange(8), round=rng.randrange(6),
                       units=rng.randint(1, 10), verdict=rng.choice(["ALLOW", "DENY"]), spent=rng.randint(0, 100))
        append_ops = counter.calls
        counter.calls = 0
        res = log.verify_full()
        verify_ops = counter.calls
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    total_bytes = sum(len(json.dumps(e, sort_keys=True)) + 1 for e in log.entries)
    entries = len(log.entries)
    return {"appended": n, "entries": entries, "checkpoints": res.checkpoints, "verify_ok": res.ok,
            "total_bytes": total_bytes, "bytes_per_entry": total_bytes / entries,
            "append_hash_ops": append_ops, "append_hash_ops_per_entry": append_ops / entries,
            "verify_hash_ops": verify_ops, "verify_hash_ops_per_entry": verify_ops / entries}


def simulate(seed: int, scales: tuple[int, ...] = SCALES) -> dict:
    per = {str(n): _measure(n, seed) for n in scales}
    lo, hi = per[str(scales[0])], per[str(scales[-1])]
    return {"scales": per,
            "bytes_per_entry_ratio_100k_over_1k": hi["bytes_per_entry"] / lo["bytes_per_entry"],
            "verify_ops_per_entry_ratio_100k_over_1k":
                hi["verify_hash_ops_per_entry"] / lo["verify_hash_ops_per_entry"],
            "all_verify_ok": all(v["verify_ok"] for v in per.values())}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.audit_overhead")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = {"audit_overhead": simulate(args.seed)}
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.audit_overhead "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/pdf/2609.00275", "license": "none used; simulated data only"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
