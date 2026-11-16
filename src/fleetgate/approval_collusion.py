"""Colluding approvers against the real ApprovalQueue and N-of-M pools, with and without a roster check.

``Approval.role`` is self-declared, so the queue only enforces *distinct names* and *eligible role strings*. Attack arms
(each round files one request needing the default DESTRUCTIVE pool plus the protected pool through ``ApprovalQueue``):
``duplicate_name`` (one name votes many times, with random eligible roles), ``wrong_role_sybil`` (distinct names, roles
outside the requirement), ``forged_role_sybil`` (distinct names that declare eligible roles, covering every eligible
role at least once). The ``roster`` condition wraps the approver and drops votes whose (name, role) is not registered.
``honest`` is a control with registered approvers. Simulated data only; every arm's audit log is verified.
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
from typing import Any

from .approvals import Approval, ApprovalQueue, ApprovalRequest, ScriptedApprover
from .audit import AuditLog
from .policy import ApprovalRequirement, Reason

ROSTER = {("alice", "sre-lead"), ("bob", "dc-ops"), ("carol", "db-owner"), ("dave", "dc-ops")}
HONEST_VOTES = [("alice", "sre-lead", True), ("bob", "dc-ops", True), ("carol", "db-owner", True)]
WRONG_ROLES = ("intern", "contractor", "observer", "auditor")
ARMS = ("duplicate_name", "wrong_role_sybil", "forged_role_sybil", "honest")


def requirement() -> ApprovalRequirement:
    from .policy import PolicyConfig

    approvals = PolicyConfig().approvals
    pools = [(approvals[t]["required"], tuple(approvals[t]["roles"])) for t in ("DESTRUCTIVE", "protected")]
    return ApprovalRequirement.from_pools(pools, Reason.DESTRUCTIVE_TIER)


class RosterApprover:
    """Wraps an approver and keeps only votes whose (name, role) pair is registered."""

    def __init__(self, inner: Any, roster: set[tuple[str, str]]):
        self.inner, self.roster = inner, roster

    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        return [a for a in self.inner.review(request, tick) if (a.approver, a.role) in self.roster]


def votes_for(arm: str, rng: random.Random, roles: tuple[str, ...]) -> list[tuple[str, str, bool]]:
    k = rng.randint(3, 6)
    if arm == "duplicate_name":
        return [("mallory", rng.choice(roles), True) for _ in range(k)]
    if arm == "wrong_role_sybil":
        return [(f"sybil-{i}", rng.choice(WRONG_ROLES), True) for i in range(k)]
    if arm == "forged_role_sybil":
        rs = list(roles) + [rng.choice(roles) for _ in range(k - len(roles))]
        rng.shuffle(rs)
        return [(f"sybil-{i}", r, True) for i, r in enumerate(rs)]
    return list(HONEST_VOTES)


def run_arm(arm: str, rounds: int, seed: int, roster: bool) -> dict:
    rng = random.Random(f"{seed}:{arm}:{roster}")
    req = requirement()
    log = AuditLog(checkpoint_every=64)
    approved = 0
    for i in range(rounds):
        approver: Any = ScriptedApprover(votes_for(arm, rng, req.roles))
        if roster:
            approver = RosterApprover(approver, ROSTER)
        r = ApprovalQueue(approver).submit(f"inc-{i}", "wipe_disk", "db-1", "sim", req, tick=0)
        approved += r.status == "approved"
        log.append("approval_round", arm=arm, round=i, status=r.status, votes=len(r.approvals))
    res = log.verify_full()
    return {"rounds": rounds, "approved": approved, "rate": approved / rounds, "verify_ok": res.ok}


def simulate(seed: int, rounds: int) -> dict:
    req = requirement()
    no_roster = {a: run_arm(a, rounds, seed, False) for a in ARMS}
    roster = {a: run_arm(a, rounds, seed, True) for a in ARMS}
    return {
        "rounds": rounds, "requirement": req.to_dict(),
        "approval_bypass_rate": {a: no_roster[a]["rate"] for a in ARMS if a != "honest"},
        "approval_bypass_rate_roster": {a: roster[a]["rate"] for a in ARMS if a != "honest"},
        "honest_approval_rate": {"no_roster": no_roster["honest"]["rate"], "roster": roster["honest"]["rate"]},
        "arms": {"no_roster": no_roster, "roster": roster},
        "all_logs_verify": all(v["verify_ok"] for d in (no_roster, roster) for v in d.values()),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.approval_collusion")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.approval_collusion "
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
