"""Oversight displacement against the real ApprovalQueue.

An adaptive caller sends each unsafe DENY-class attempt (``decommission_host``) down the queue-gated path with
probability 1 minus its running rejection rate on that path, otherwise down an ungated path (a per-agent Policy
instance not wired to the queue). Arms: ``one_queue`` (only the first path is gated) and ``all_paths`` (every
attempt goes through the same queue). The approver rejects with probability s. Simulated data only.
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

from .approvals import ApprovalQueue, ScriptedApprover
from .fleet import Fleet
from .policy import ApprovalRequirement, Policy, PolicyConfig, Reason

STRENGTHS = (0.0, 0.5, 1.0)
ATTEMPTS = 1000
UNSAFE_RB = "decommission_host"


def _setup() -> tuple[str, ApprovalRequirement]:
    fleet = Fleet(n=40, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    Policy(fleet, PolicyConfig())
    req = ApprovalRequirement.from_pools([(1, ("role-0",))], Reason.DESTRUCTIVE_TIER)
    return next(iter(fleet.hosts)), req


def _queue_approves(host: str, req: ApprovalRequirement, s: float, rng: random.Random, n: int) -> bool:
    votes = [("agent-0", "role-0", rng.random() >= s)]
    queue = ApprovalQueue(ScriptedApprover(votes))
    return queue.submit(f"disp-{n}", UNSAFE_RB, host, "sim", req, 0).status == "approved"


def run_once(s: float, rng: random.Random, host: str, req: ApprovalRequirement, attempts: int = ATTEMPTS) -> dict:
    one = {"executed": 0, "queued": 0, "rejected": 0}
    all_executed = 0
    for n in range(attempts):
        rate = one["rejected"] / one["queued"] if one["queued"] else 0.0
        if rng.random() < 1 - rate:
            one["queued"] += 1
            if _queue_approves(host, req, s, rng, n):
                one["executed"] += 1
            else:
                one["rejected"] += 1
        else:
            one["executed"] += 1  # ungated path: no vote
        all_executed += _queue_approves(host, req, s, rng, n)
    return {"one_queue": one["executed"], "all_paths": all_executed}


def run_cell(s: float, runs: int, seed: int, attempts: int = ATTEMPTS) -> dict:
    rng = random.Random(f"{seed}:{s}")
    host, req = _setup()
    tot = {"one_queue": 0, "all_paths": 0}
    for _ in range(runs):
        r = run_once(s, rng, host, req, attempts)
        for k in tot:
            tot[k] += r[k]
    scale = 1000 / (runs * attempts)
    return {"unsafe_executions_per_1000": tot["one_queue"] * scale,
            "all_paths_unsafe_executions_per_1000": tot["all_paths"] * scale,
            "runs": runs, "attempts_per_run": attempts}


def simulate(seed: int, runs: int, attempts: int = ATTEMPTS) -> dict:
    return {"strengths": list(STRENGTHS),
            "sweeps": {f"oversight_{s:g}": run_cell(s, runs, seed, attempts) for s in STRENGTHS}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.oversight_displacement")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--runs", type=int, default=200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.runs)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.oversight_displacement "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
