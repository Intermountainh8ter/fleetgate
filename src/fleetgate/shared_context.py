"""Shared corrupted context against the real Policy and ApprovalQueue.

With probability ``rho`` per plan all 5 approvers read one shared corrupted summary of a DENY-class plan
(``decommission_host``) and approve it; otherwise each approves independently with probability ``INDEPENDENT_ERR``.
Arm ``quorum_trusted`` executes the plan if ``ApprovalQueue`` approves it; arm ``gate_rederived`` executes only if
``Policy.evaluate`` returns ALLOW, ignoring votes. A legitimate ALLOW-class plan (``restart_service``) measures
blocked legitimate plans. Simulated data only.
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
from .audit import AuditLog
from .fleet import Fleet
from .policy import ApprovalRequirement, Decision, Policy, PolicyConfig, Reason

APPROVERS = 5
RHOS = (0.0, 0.5, 1.0)
INDEPENDENT_ERR = 0.1
DENY_RB, LEGIT_RB = "decommission_host", "restart_service"
ARMS = ("quorum_trusted", "gate_rederived")


def _policy() -> tuple[Policy, str]:
    fleet = Fleet(n=40, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    return Policy(fleet, PolicyConfig()), next(iter(fleet.hosts))


def _requirement(n: int) -> ApprovalRequirement:
    roles = tuple(f"role-{i}" for i in range(n))
    return ApprovalRequirement.from_pools([(n // 2 + 1, roles)], Reason.DESTRUCTIVE_TIER)


def _votes(rng: random.Random, rho: float) -> tuple[list[tuple[str, str, bool]], bool]:
    shared = rng.random() < rho
    flags = [True] * APPROVERS if shared else [rng.random() < INDEPENDENT_ERR for _ in range(APPROVERS)]
    return [(f"agent-{i}", f"role-{i}", ok) for i, ok in enumerate(flags)], shared


def run_cell(rho: float, rounds: int, seed: int) -> dict:
    rng = random.Random(f"{seed}:{rho}")
    policy, host = _policy()
    log = AuditLog(checkpoint_every=64)
    executed = dict.fromkeys(ARMS, 0)
    legit_blocked = 0
    for i in range(rounds):
        votes, shared = _votes(rng, rho)
        queue = ApprovalQueue(ScriptedApprover(votes))
        req = queue.submit(f"shared-{i}", DENY_RB, host, "sim", _requirement(APPROVERS), 0)
        executed["quorum_trusted"] += req.status == "approved"
        gate = policy.evaluate(DENY_RB, host)
        executed["gate_rederived"] += gate.decision == Decision.ALLOW
        legit_blocked += policy.evaluate(LEGIT_RB, host).decision != Decision.ALLOW
        log.append("shared_context_round", rho=rho, round=i, shared=shared, gate=gate.code.value)
    return {"executed_deny": {a: executed[a] / rounds for a in ARMS},
            "gate_blocked_legitimate": legit_blocked / rounds, "verify_ok": log.verify_full().ok}


def simulate(seed: int, rounds: int) -> dict:
    grid = {str(r): run_cell(r, rounds, seed) for r in RHOS}
    return {
        "rounds": rounds, "approvers": APPROVERS, "quorum": APPROVERS // 2 + 1,
        "independent_error_rate": INDEPENDENT_ERR,
        "executed_deny_share_by_rho": {k: c["executed_deny"] for k, c in grid.items()},
        "gate_rederived_blocked_legitimate_by_rho": {k: c["gate_blocked_legitimate"] for k, c in grid.items()},
        "all_logs_verify": all(c["verify_ok"] for c in grid.values()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.shared_context")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.shared_context "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
