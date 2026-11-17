"""Approval fatigue against the real Policy and ApprovalQueue.

An approver's probability of rejecting an unsafe DENY-class plan (``decommission_host``) decays as
``BASE_REJECT * exp(-d * n)`` with the number n of requests already handled in a 100-request shift. Arms: one
approver, two independent fatigued approvers (any reject vetoes, as in ``ApprovalQueue``), and ``gate_rederived``
which takes ``Policy.evaluate`` and ignores votes. Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import math
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .approvals import ApprovalQueue, ScriptedApprover
from .fleet import Fleet
from .policy import ApprovalRequirement, Decision, Policy, PolicyConfig, Reason

SHIFT = 100
DECAYS = (0.0, 0.01, 0.05)
BASE_REJECT = 0.9
UNSAFE_RB = "decommission_host"


def _policy() -> tuple[Policy, str]:
    fleet = Fleet(n=40, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    return Policy(fleet, PolicyConfig()), next(iter(fleet.hosts))


def _requirement(n: int) -> ApprovalRequirement:
    roles = tuple(f"role-{i}" for i in range(n))
    return ApprovalRequirement.from_pools([(n // 2 + 1, roles)], Reason.DESTRUCTIVE_TIER)


def reject_probability(d: float, n: int) -> float:
    return BASE_REJECT * math.exp(-d * n)


def analytic_single(d: float, shift: int = SHIFT) -> float:
    return 1 - sum(reject_probability(d, n) for n in range(shift)) / shift


def run_cell(d: float, shifts: int, seed: int, shift: int = SHIFT) -> dict:
    rng = random.Random(f"{seed}:{d}")
    policy, host = _policy()
    approved = {1: 0, 2: 0}
    gate_exec = 0
    total = shifts * shift
    for _ in range(shifts):
        for n in range(shift):
            p = reject_probability(d, n)
            for k in (1, 2):
                votes = [(f"agent-{i}", f"role-{i}", rng.random() >= p) for i in range(k)]
                queue = ApprovalQueue(ScriptedApprover(votes))
                req = queue.submit(f"fatigue-{n}", UNSAFE_RB, host, "sim", _requirement(k), 0)
                approved[k] += req.status == "approved"
            gate_exec += policy.evaluate(UNSAFE_RB, host).decision == Decision.ALLOW
    return {
        "unsafe_approval_rate": approved[1] / total,
        "two_approver_unsafe_approval_rate": approved[2] / total,
        "analytic_single": analytic_single(d, shift),
        "gate_rederived_executed_unsafe": gate_exec,
        "requests": total,
    }


def simulate(seed: int, shifts: int) -> dict:
    return {"shift_length": SHIFT, "shifts": shifts, "base_reject": BASE_REJECT,
            "sweeps": {f"decay_{d:g}": run_cell(d, shifts, seed) for d in DECAYS}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.approval_fatigue")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--shifts", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.shifts)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.approval_fatigue "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
