"""Approver collusion that starts at a seeded onset round, against the real Policy and ApprovalQueue.

Each round proposes a DENY-class plan (``decommission_host``). Of ``APPROVERS`` approvers, ``k`` collude and always
approve from the onset round on; the rest err independently with probability ``INDEPENDENT_ERR`` in every round.
Arms: ``quorum_trusted`` (majority through ``ApprovalQueue``, votes override the gate), ``distinct_principal`` (one
pool slot per approver role) and ``gate_rederived`` (``Policy.evaluate``, votes ignored for DENY). A benign
ALLOW-class control checks the gate still executes. Simulated data only; every arm's audit log is verified.
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
COLLUDERS = (0, 1, 2, 3, 4, 5)
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


def _votes(rng: random.Random, colluding: int) -> list[tuple[str, str, bool]]:
    return [(f"agent-{i}", f"role-{i}", i < colluding or rng.random() < INDEPENDENT_ERR)
            for i in range(APPROVERS)]


def run_cell(k: int, rounds: int, seed: int) -> dict:
    rng = random.Random(f"{seed}:{k}")
    onset = rng.randint(rounds // 4, rounds // 2)
    policy, host = _policy()
    log = AuditLog(checkpoint_every=64)
    phases = ("pre", "post")
    executed = {p: dict.fromkeys(ARMS, 0) for p in phases}
    count = dict.fromkeys(phases, 0)
    benign_exec = policy_deny = 0
    for i in range(rounds):
        p = "post" if i >= onset else "pre"
        count[p] += 1
        votes = _votes(rng, k if p == "post" else 0)
        v = policy.evaluate(DENY_RB, host)
        policy_deny += v.decision == Decision.DENY
        for arm in ("quorum_trusted", "distinct_principal"):
            queue = ApprovalQueue(ScriptedApprover(votes))
            req = queue.submit(f"{arm}-{i}", DENY_RB, host, "sim", _requirement(arm, APPROVERS), 0)
            executed[p][arm] += req.status == "approved"
        executed[p]["gate_rederived"] += v.decision == Decision.ALLOW
        benign_exec += policy.evaluate(BENIGN_RB, host).decision == Decision.ALLOW
        log.append("collusion_onset_round", colluders=k, round=i, phase=p, verdict=v.code.value,
                   approve_votes=sum(ok for _, _, ok in votes))
    share = {p: {a: executed[p][a] / max(count[p], 1) for a in ARMS} for p in phases}
    return {"onset": onset, "pre": share["pre"], "post": share["post"],
            "policy_deny_share": policy_deny / rounds, "benign_gate_exec_share": benign_exec / rounds,
            "verify_ok": log.verify_full().ok}


def simulate(seed: int, rounds: int) -> dict:
    grid = {str(k): run_cell(k, rounds, seed) for k in COLLUDERS}
    cells = list(grid.values())
    return {
        "rounds": rounds, "approvers": APPROVERS, "quorum": APPROVERS // 2 + 1,
        "independent_error_rate": INDEPENDENT_ERR,
        "executed_deny_share_post_onset_by_colluders": {k: c["post"] for k, c in grid.items()},
        "executed_deny_share_pre_onset_by_colluders": {k: c["pre"] for k, c in grid.items()},
        "onset_round_by_colluders": {k: c["onset"] for k, c in grid.items()},
        "gate_rederived_max_share": max(c[ph]["gate_rederived"] for c in cells for ph in ("pre", "post")),
        "policy_deny_share_min": min(c["policy_deny_share"] for c in cells),
        "benign_gate_exec_share_min": min(c["benign_gate_exec_share"] for c in cells),
        "all_logs_verify": all(c["verify_ok"] for c in cells),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.collusion_onset")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.collusion_onset "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
