"""Approvers that share one corrupted upstream input, against the real Policy and ApprovalQueue.

Each round proposes a DENY-class plan (``decommission_host``, on the policy deny-list). With probability ``shared`` the
round's upstream input is corrupted and every approver sees it and approves; otherwise each approver errs
independently with probability ``INDEPENDENT_ERR``. Arms: ``quorum_trusted`` (majority of N through ``ApprovalQueue``,
votes override the gate), ``distinct_principal`` (one pool slot per approver, each with its own role), and
``gate_rederived`` (``Policy.evaluate`` on the plan, votes ignored for DENY). A benign ALLOW-class control checks
the gate still executes. Simulated data only; every arm's audit log is verified.
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

SHARED = (0.0, 0.25, 0.5, 0.75, 1.0)
APPROVERS = (1, 3, 5, 9)
HEADLINE = (1.0, 5)
INDEPENDENT_ERR = 0.1
DENY_RB, BENIGN_RB = "decommission_host", "restart_service"
ARMS = ("quorum_trusted", "distinct_principal", "gate_rederived")


def _policy() -> tuple[Policy, str]:
    fleet = Fleet(n=40, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    return Policy(fleet, PolicyConfig()), next(iter(fleet.hosts))


def _requirement(arm: str, n: int) -> ApprovalRequirement:
    if arm == "distinct_principal":
        pools = [(1, (f"role-{i}",)) for i in range(n)][: n // 2 + 1]
        return ApprovalRequirement.from_pools(pools, Reason.DESTRUCTIVE_TIER)
    roles = tuple(f"role-{i}" for i in range(n))
    return ApprovalRequirement.from_pools([(n // 2 + 1, roles)], Reason.DESTRUCTIVE_TIER)


def _votes(rng: random.Random, n: int, shared: float) -> list[tuple[str, str, bool]]:
    corrupted = rng.random() < shared
    return [(f"agent-{i}", f"role-{i}", corrupted or rng.random() < INDEPENDENT_ERR) for i in range(n)]


def run_cell(shared: float, n: int, rounds: int, seed: int) -> dict:
    rng = random.Random(f"{seed}:{shared}:{n}")
    policy, host = _policy()
    log = AuditLog(checkpoint_every=64)
    executed = dict.fromkeys(ARMS, 0)
    policy_deny = benign_exec = 0
    for i in range(rounds):
        votes = _votes(rng, n, shared)
        v = policy.evaluate(DENY_RB, host)
        policy_deny += v.decision == Decision.DENY
        for arm in ("quorum_trusted", "distinct_principal"):
            queue = ApprovalQueue(ScriptedApprover(votes))
            req = queue.submit(f"{arm}-{i}", DENY_RB, host, "sim", _requirement(arm, n), 0)
            executed[arm] += req.status == "approved"
        executed["gate_rederived"] += v.decision == Decision.ALLOW
        benign_exec += policy.evaluate(BENIGN_RB, host).decision == Decision.ALLOW
        log.append("shared_quorum_round", shared=shared, approvers=n, round=i, verdict=v.code.value,
                   approve_votes=sum(ok for _, _, ok in votes))
    return {"executed_deny_share": {a: executed[a] / rounds for a in ARMS},
            "single_approver_share": sum(_votes(random.Random(f"{seed}:{shared}:s"), 1, shared)[0][2]
                                         for _ in range(rounds)) / rounds,
            "policy_deny_share": policy_deny / rounds, "benign_gate_exec_share": benign_exec / rounds,
            "verify_ok": log.verify_full().ok}


def simulate(seed: int, rounds: int) -> dict:
    grid = {f"{s}": {str(n): run_cell(s, n, rounds, seed) for n in APPROVERS} for s in SHARED}
    head = grid[str(HEADLINE[0])][str(HEADLINE[1])]
    cells = [c for row in grid.values() for c in row.values()]
    return {
        "rounds": rounds, "independent_error_rate": INDEPENDENT_ERR, "headline_cell": {
            "shared": HEADLINE[0], "approvers": HEADLINE[1]},
        "executed_deny_share_by_arm": head["executed_deny_share"],
        "single_approver_share": head["single_approver_share"],
        "quorum_trusted_by_approvers_at_shared_1": {
            str(n): grid["1.0"][str(n)]["executed_deny_share"]["quorum_trusted"] for n in APPROVERS},
        "gate_rederived_max_share": max(c["executed_deny_share"]["gate_rederived"] for c in cells),
        "policy_deny_share_min": min(c["policy_deny_share"] for c in cells),
        "benign_gate_exec_share_min": min(c["benign_gate_exec_share"] for c in cells),
        "grid": grid, "all_logs_verify": all(c["verify_ok"] for c in cells),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.shared_quorum")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.shared_quorum "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-process generator, no external data",
                          "license": "MIT (own code)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
