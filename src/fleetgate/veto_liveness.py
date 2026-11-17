"""Veto collusion against the real Policy and ApprovalQueue: v of 5 approvers always reject.

Each round proposes a legitimate plan (``restart_service``, ALLOW-class at the gate). Arm ``quorum_trusted`` routes it
through ``ApprovalQueue`` with a quorum of 3, so any reject vote blocks it; arm ``gate_rederived`` takes
``Policy.evaluate`` and ignores votes. A DENY-class plan (``decommission_host``) checks that the gate never executes
it. Vote order is seeded random; honest approvers reject independently with probability ``INDEPENDENT_ERR``.
Simulated data only.
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
VETOERS = (0, 1, 2, 3, 4)
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


def _votes(rng: random.Random, vetoers: int) -> list[tuple[str, str, bool]]:
    flags = [False] * vetoers + [rng.random() >= INDEPENDENT_ERR for _ in range(APPROVERS - vetoers)]
    rng.shuffle(flags)
    return [(f"agent-{i}", f"role-{i}", ok) for i, ok in enumerate(flags)]


def run_cell(v: int, rounds: int, seed: int) -> dict:
    rng = random.Random(f"{seed}:{v}")
    policy, host = _policy()
    log = AuditLog(checkpoint_every=64)
    blocked = dict.fromkeys(ARMS, 0)
    deny_exec = 0
    for i in range(rounds):
        votes = _votes(rng, v)
        queue = ApprovalQueue(ScriptedApprover(votes))
        req = queue.submit(f"veto-{i}", LEGIT_RB, host, "sim", _requirement(APPROVERS), 0)
        blocked["quorum_trusted"] += req.status != "approved"
        gate = policy.evaluate(LEGIT_RB, host)
        blocked["gate_rederived"] += gate.decision != Decision.ALLOW
        deny_exec += policy.evaluate(DENY_RB, host).decision == Decision.ALLOW
        log.append("veto_liveness_round", vetoers=v, round=i, gate=gate.code.value,
                   approve_votes=sum(ok for _, _, ok in votes))
    return {"blocked": {a: blocked[a] / rounds for a in ARMS}, "gate_executed_deny": deny_exec,
            "verify_ok": log.verify_full().ok}


def simulate(seed: int, rounds: int) -> dict:
    grid = {str(v): run_cell(v, rounds, seed) for v in VETOERS}
    return {
        "rounds": rounds, "approvers": APPROVERS, "quorum": APPROVERS // 2 + 1,
        "independent_error_rate": INDEPENDENT_ERR,
        "blocked_legitimate_share_by_veto": {k: c["blocked"] for k, c in grid.items()},
        "gate_rederived_executed_deny_total": sum(c["gate_executed_deny"] for c in grid.values()),
        "all_logs_verify": all(c["verify_ok"] for c in grid.values()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.veto_liveness")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.veto_liveness "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
