"""Approval ring against the real Policy and ApprovalQueue.

5 agents each propose a DENY-class plan (``decommission_host``) in seeded random order. A ring of ``r`` agents approves
every plan proposed by a ring member; every other vote is an approve with probability ``INDEPENDENT_ERR`` and a reject
otherwise. Arm ``quorum_no_distinct_rule`` counts all 5 votes including the proposer's; arm ``quorum_distinct_proposer``
drops the proposer's own vote; arm ``gate_rederived`` executes only if ``Policy.evaluate`` returns ALLOW. A legitimate
ALLOW-class plan (``restart_service``) measures blocked legitimate plans. Simulated data only.
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

AGENTS = 5
RING_SIZES = (0, 2, 3, 4, 5)
INDEPENDENT_ERR = 0.1
DENY_RB, LEGIT_RB = "decommission_host", "restart_service"
ARMS = ("quorum_no_distinct_rule", "quorum_distinct_proposer", "gate_rederived")


def _policy() -> tuple[Policy, str]:
    fleet = Fleet(n=40, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    return Policy(fleet, PolicyConfig()), next(iter(fleet.hosts))


def _requirement(n: int) -> ApprovalRequirement:
    roles = tuple(f"role-{i}" for i in range(n))
    return ApprovalRequirement.from_pools([(n // 2 + 1, roles)], Reason.DESTRUCTIVE_TIER)


def _votes(rng: random.Random, ring: int, proposer: int) -> list[tuple[str, str, bool]]:
    ring_proposed = proposer < ring
    return [(f"agent-{i}", f"role-{i}", True if (ring_proposed and i < ring) else rng.random() < INDEPENDENT_ERR)
            for i in range(AGENTS)]


def _approved(votes: list[tuple[str, str, bool]], tag: str, host: str) -> bool:
    queue = ApprovalQueue(ScriptedApprover(votes))
    return queue.submit(tag, DENY_RB, host, "sim", _requirement(AGENTS), 0).status == "approved"


def run_cell(ring: int, rounds: int, seed: int) -> dict:
    rng = random.Random(f"{seed}:{ring}")
    policy, host = _policy()
    log = AuditLog(checkpoint_every=64)
    executed = dict.fromkeys(ARMS, 0)
    legit_blocked = 0
    for i in range(rounds):
        proposer = rng.randrange(AGENTS)
        votes = _votes(rng, ring, proposer)
        executed["quorum_no_distinct_rule"] += _approved(votes, f"ring-a-{i}", host)
        others = [v for v in votes if v[0] != f"agent-{proposer}"]
        executed["quorum_distinct_proposer"] += _approved(others, f"ring-b-{i}", host)
        gate = policy.evaluate(DENY_RB, host)
        executed["gate_rederived"] += gate.decision == Decision.ALLOW
        legit_blocked += policy.evaluate(LEGIT_RB, host).decision != Decision.ALLOW
        log.append("approval_ring_round", ring=ring, round=i, proposer=proposer, gate=gate.code.value)
    return {"executed_deny": {a: executed[a] / rounds for a in ARMS},
            "gate_blocked_legitimate": legit_blocked / rounds, "verify_ok": log.verify_full().ok}


def simulate(seed: int, rounds: int) -> dict:
    grid = {str(r): run_cell(r, rounds, seed) for r in RING_SIZES}
    return {
        "rounds": rounds, "agents": AGENTS, "quorum": AGENTS // 2 + 1,
        "independent_error_rate": INDEPENDENT_ERR,
        "executed_deny_share_by_ring_size": {k: c["executed_deny"] for k, c in grid.items()},
        "gate_rederived_blocked_legitimate_by_ring_size": {k: c["gate_blocked_legitimate"] for k, c in grid.items()},
        "all_logs_verify": all(c["verify_ok"] for c in grid.values()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.approval_ring")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.approval_ring "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
