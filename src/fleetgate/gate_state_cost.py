"""SHA-256 operations per gate decision for stateless, in-memory and log-derived stateful gates.

The log-derived arms read caller history from the audit log: one re-verifies the whole log first, the other only
from the latest checkpoint. Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from . import audit
from .audit import AuditLog
from .audit_suffix import _CountingHashlib, suffix_verify

SCALES = (1_000, 10_000, 100_000)
TAIL = 20
DECISIONS = 500
TAMPERS = 200
WINDOW = 64
CAP = 1_000  # above WINDOW * max units (10), so history never binds in the seeded workload
ARMS = ("stateless", "in_memory", "log_derived_full", "log_derived_suffix")


def _build(n: int, seed: int):
    rng = random.Random(seed * 1_000_003 + n)
    log = AuditLog(checkpoint_every=32)
    recent: deque = deque(maxlen=WINDOW)

    def add() -> None:
        agent, units = rng.randrange(8), rng.randint(1, 10)
        log.append("collusion_verdict", agent=agent, units=units)
        recent.append((agent, units))

    while len(log.entries) < n:
        add()
    cp = log.checkpoint()
    for _ in range(TAIL):
        add()
    return log, cp["seq"], cp["hash"], recent


def _spent(entries, agent: int) -> int:
    return sum(e.get("units", 0) for e in entries[-WINDOW:] if e.get("agent") == agent)


def _verdict(spent: int, units: int) -> str:
    return "ALLOW" if spent + units <= CAP else "DENY"


def _decide(arm: str, log, aseq, ahash, recent, agent: int, units: int) -> str | None:
    """Verdict, or None when the arm refuses because its log verification failed."""
    if arm == "stateless":
        return _verdict(0, units)
    if arm == "in_memory":
        return _verdict(sum(u for a, u in recent if a == agent), units)
    if arm == "log_derived_full":
        ok = log.verify_full().ok
    else:
        ok = suffix_verify(log.entries, aseq, ahash)
    return _verdict(_spent(log.entries, agent), units) if ok else None


def _measure(n: int, seed: int) -> dict:
    log, aseq, ahash, recent = _build(n, seed)
    rng = random.Random(seed * 7_919 + n)
    reqs = [(rng.randrange(8), rng.randint(1, 10)) for _ in range(DECISIONS)]
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        ops, verdicts = {}, {}
        for arm in ARMS:
            counter.calls = 0
            verdicts[arm] = [_decide(arm, log, aseq, ahash, recent, a, u) for a, u in reqs]
            ops[arm] = counter.calls / DECISIONS
        refused = dict.fromkeys(ARMS, 0)
        for _ in range(TAMPERS):
            i = rng.randrange(0, aseq)
            if log.entries[i]["kind"] == "checkpoint":
                i -= 1
            old = log.entries[i].get("units")
            log.entries[i]["units"] = (old or 0) + 1
            a, u = rng.randrange(8), rng.randint(1, 10)
            for arm in ARMS:
                refused[arm] += _decide(arm, log, aseq, ahash, recent, a, u) is None
            log.entries[i]["units"] = old
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    return {"entries": len(log.entries), "ops": ops,
            "verdicts_identical": all(verdicts[a] == verdicts["stateless"] for a in ARMS),
            "refusal_rate_after_tamper": {arm: refused[arm] / TAMPERS for arm in ARMS}}


def simulate(seed: int, scales: tuple[int, ...] = SCALES) -> dict:
    per = {str(n): _measure(n, seed) for n in scales}
    return {"scales": per,
            "ops_per_decision_by_arm": {arm: {str(n): per[str(n)]["ops"][arm] for n in scales} for arm in ARMS},
            "refusal_rate_after_tamper_by_arm": {arm: {str(n): per[str(n)]["refusal_rate_after_tamper"][arm]
                                                       for n in scales} for arm in ARMS},
            "verdicts_identical_all_scales": all(v["verdicts_identical"] for v in per.values()),
            "decisions_per_scale": DECISIONS, "tampers_per_scale": TAMPERS}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.gate_state_cost")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.gate_state_cost "
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
