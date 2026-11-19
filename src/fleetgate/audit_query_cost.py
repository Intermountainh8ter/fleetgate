"""Records scanned and SHA-256 operations to answer one per-agent audit query: full-chain scan versus index plus proofs.

Counts only, no wall-clock. Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import audit
from .audit import AuditLog
from .audit_fleet_cost import _CACHE, CHECKPOINT_EVERY, FLEET_SIZES, _levels, reconstruct
from .audit_suffix import _CountingHashlib

QUERIES = 50


def _next_cp(entries: list[dict], i: int):
    return next((j for j in range(i + 1, len(entries)) if entries[j]["kind"] == "checkpoint"), None)


def _measure(agents: int, per_agent: int, seed: int) -> dict:
    rng = random.Random(seed * 1_000_003 + agents)
    order = [a for a in range(agents) for _ in range(per_agent)]
    rng.shuffle(order)
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        _CACHE.clear()
        log = AuditLog(checkpoint_every=CHECKPOINT_EVERY)
        for a in order:
            log.append("gate_decision", agent=a, units=rng.randint(1, 10), verdict=rng.choice(["ALLOW", "DENY"]))
        entries = log.entries
        index: dict[int, list[int]] = {}
        for i, e in enumerate(entries):
            if e["kind"] != "checkpoint":
                index.setdefault(e["agent"], []).append(i)
        counter.calls = 0
        full_ok = log.verify_full().ok
        full_ops = counter.calls
        queried = sorted(rng.sample(range(agents), min(QUERIES, agents)))
        for a in queried:  # warm prover trees outside the count
            for i in index[a]:
                cp = _next_cp(entries, i)
                if cp is not None:
                    _levels(entries, entries[cp]["block_start"], entries[cp]["block_end"])
        idx_ops = idx_scanned = 0
        identical = proofs_ok = True
        for a in queried:
            full_set = [e["hash"] for e in entries if e["kind"] != "checkpoint" and e["agent"] == a]
            counter.calls = 0
            rows = index[a]
            proofs_ok = proofs_ok and all(reconstruct(entries, i) for i in rows)
            idx_ops += counter.calls
            idx_scanned += len(rows)
            identical = identical and [entries[i]["hash"] for i in rows] == full_set
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    q = len(queried)
    return {"entries": len(entries), "full_verify_ok": full_ok, "full_ops": full_ops,
            "index_ops_per_query": idx_ops / q, "index_scanned_per_query": idx_scanned / q,
            "identical_record_sets": identical, "proofs_ok": proofs_ok, "queries": q}


def simulate(seed: int, per_agent: int = 20, sizes: tuple[int, ...] = FLEET_SIZES) -> dict:
    per = {str(a): _measure(a, per_agent, seed) for a in sizes}
    lo, hi = str(sizes[0]), str(sizes[-1])
    return {"records_scanned_per_query": {"full_scan": {k: v["entries"] for k, v in per.items()},
                                          "index": {k: v["index_scanned_per_query"] for k, v in per.items()}},
            "sha256_ops_per_query": {"full_scan": {k: v["full_ops"] for k, v in per.items()},
                                     "index": {k: v["index_ops_per_query"] for k, v in per.items()}},
            "index_to_full_sha256_ratio_largest": per[hi]["full_ops"] / per[hi]["index_ops_per_query"],
            "full_scan_records_ratio_largest_to_smallest": per[hi]["entries"] / per[lo]["entries"],
            "fleet_size_ratio_largest_to_smallest": int(hi) / int(lo),
            "all_record_sets_identical": all(v["identical_record_sets"] for v in per.values()),
            "all_verifications_ok": all(v["full_verify_ok"] and v["proofs_ok"] for v in per.values()),
            "per_fleet_size": per, "decisions_per_agent": per_agent, "queries_per_fleet_size": QUERIES}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.audit_query_cost")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--decisions-per-agent", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.decisions_per_agent)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.audit_query_cost "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-process audit logs, no external data",
                          "license": "MIT (repository code)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
