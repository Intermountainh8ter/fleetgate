"""Seeded stale-approval rounds against the real Policy.evaluate and ApprovalRequirement.

Each round, one DISRUPTIVE plan (a runbook the default gate sends to NEEDS_APPROVAL, on a worker host) is
approved by two distinct approvers (roles ``sre`` and ``sre-lead``) under the default Policy. Before execution the
gate's PolicyConfig is swapped for the strict bundled policy with ``raid_rebuild`` added to its deny-list.
Arms: ``trust_stored_approval`` (executes every approved plan) and ``re_evaluate`` (asks the swapped gate again
and executes on ALLOW, or on NEEDS_APPROVAL when the stored approvers satisfy the new requirement). Every
verdict and execution lands in an AuditLog whose chain is verified. Simulated data only.
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

from .audit import AuditLog
from .policy import Decision, Policy, PolicyConfig
from .runbooks import CATALOG, Tier
from .split_caller import FLEET_SIZE, _fleet

ARMS = ("trust_stored_approval", "re_evaluate")
APPROVERS = {"alice": "sre", "bob": "sre-lead"}
BANNED = "raid_rebuild"


def strict_config() -> PolicyConfig:
    cfg = PolicyConfig.load("strict")
    cfg.deny_list = set(cfg.deny_list) | {BANNED}
    return cfg


def approvable_runbooks() -> list[str]:
    """DISRUPTIVE runbooks the default gate sends to NEEDS_APPROVAL on the first worker host."""
    fleet = _fleet()
    hid = next(iter(fleet.hosts))
    return [rid for rid, rb in sorted(CATALOG.items())
            if rb.tier == Tier.DISRUPTIVE
            and Policy(fleet, PolicyConfig()).evaluate(rid, hid).decision == Decision.NEEDS_APPROVAL]


def run_plan(arm: str, runbook: str, host: str, log: AuditLog, rnd: int) -> tuple[bool, bool]:
    """Return (executed, strict_denies)."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    fleet = _fleet()
    first = Policy(fleet, PolicyConfig()).evaluate(runbook, host)
    if first.decision != Decision.NEEDS_APPROVAL or not first.requirement.satisfied_by(APPROVERS):
        raise ValueError("plan is not approvable under the default policy")
    log.append("stale_approved", arm=arm, round=rnd, runbook=runbook, host=host, code=first.code.value)
    second = Policy(fleet, strict_config()).evaluate(runbook, host)
    strict_denies = second.decision == Decision.DENY
    if arm == "trust_stored_approval":
        executed = True
    else:
        executed = second.decision == Decision.ALLOW or (
            second.decision == Decision.NEEDS_APPROVAL and second.requirement.satisfied_by(APPROVERS))
    log.append("stale_verdict", arm=arm, round=rnd, code=second.code.value, executed=executed)
    return executed, strict_denies


def simulate(seed: int, rounds: int = 1000) -> dict:
    rng = random.Random(seed)
    pool = approvable_runbooks()
    host_ids = list(_fleet().hosts)
    plan = [(rng.choice(pool), rng.choice(host_ids)) for _ in range(rounds)]
    stats, verified, entries = {}, {}, {}
    flags = {}
    for arm in ARMS:
        log = AuditLog()
        res = [run_plan(arm, r, h, log, i) for i, (r, h) in enumerate(plan)]
        flags[arm] = res
        denied = [ex for ex, d in res if d]
        allowed = [ex for ex, d in res if not d]
        stats[arm] = {"denied_plans": len(denied), "denied_executed": sum(denied),
                      "allowed_plans": len(allowed), "allowed_executed": sum(allowed)}
        verified[arm] = bool(log.verify_full().ok)
        entries[arm] = sum(e["kind"] == "stale_verdict" for e in log.entries)
    t, r = flags["trust_stored_approval"], flags["re_evaluate"]
    still_allowed = [i for i, (_, d) in enumerate(t) if not d]
    return {
        "config": {"rounds": rounds, "fleet_size": FLEET_SIZE, "runbook_pool": pool, "banned_in_strict": BANNED,
                   "approvers": APPROVERS, "strict_policy": "strict + raid_rebuild on deny-list"},
        "stale_execute_rate_by_arm": {a: stats[a]["denied_executed"] / stats[a]["denied_plans"]
                                      if stats[a]["denied_plans"] else None for a in ARMS},
        "stats_by_arm": stats,
        "disagreements_on_still_allowed": sum(t[i][0] != r[i][0] for i in still_allowed),
        "audit_verdict_entries_by_arm": entries,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.stale_approval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.stale_approval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
