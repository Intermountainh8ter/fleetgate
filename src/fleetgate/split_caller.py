"""Seeded split-caller rounds against the real Policy.evaluate/record.

Each round, K (4..12) reversible proposals on K distinct unprotected hosts, each a different runbook so no
canary campaign forms, arrive in one tick. Arms: ``single_actor`` (one caller, one shared Policy),
``split_agents`` (K callers, one shared Policy) and ``per_agent_gate`` (K callers, one Policy instance each
over the same fleet). An ALLOW verdict is recorded as executed. Every verdict lands in an AuditLog whose
chain is verified, one decision entry per verdict (automatic checkpoint entries are counted apart). Simulated data only.
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
from .fleet import Fleet
from .policy import Decision, Policy, PolicyConfig
from .runbooks import CATALOG, Tier

FLEET_SIZE = 40
K_MIN, K_MAX = 4, 12
ARMS = ("single_actor", "shared_gate", "per_agent_gate")


def _fleet() -> Fleet:
    fleet = Fleet(n=FLEET_SIZE, seed=0)
    for h in fleet.hosts.values():
        h.role = "worker"
    return fleet


def admissible_runbooks() -> list[str]:
    """Reversible, non-draining runbooks a fresh default gate ALLOWs on the first worker host."""
    fleet = _fleet()
    hid = next(iter(fleet.hosts))
    out = []
    for rid, rb in sorted(CATALOG.items()):
        if rb.tier != Tier.REVERSIBLE or rb.drains:
            continue
        if Policy(fleet, PolicyConfig()).evaluate(rid, hid).decision == Decision.ALLOW:
            out.append(rid)
    return out


def run_round(arm: str, runbooks: list[str], hosts: list[str], log: AuditLog, rnd: int) -> int:
    """Return the number of admitted proposals."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    fleet = _fleet()
    shared = Policy(fleet, PolicyConfig())
    admitted = 0
    for agent, (rid, hid) in enumerate(zip(runbooks, hosts)):
        policy = Policy(fleet, PolicyConfig()) if arm == "per_agent_gate" else shared
        caller = 0 if arm == "single_actor" else agent
        v = policy.evaluate(rid, hid)
        log.append("split_verdict", arm=arm, round=rnd, caller=caller, code=v.code.value)
        if v.decision == Decision.ALLOW:
            admitted += 1
            policy.record(rid, hid)
    return admitted


def simulate(seed: int, rounds: int = 1000) -> dict:
    rng = random.Random(seed)
    pool = admissible_runbooks()
    if len(pool) < K_MAX:
        raise RuntimeError("not enough admissible reversible runbooks")
    host_ids = list(_fleet().hosts)
    plan = []
    for _ in range(rounds):
        k = rng.randint(K_MIN, K_MAX)
        plan.append((rng.sample(pool, k), rng.sample(host_ids, k)))
    total = sum(len(p[0]) for p in plan)
    admitted, verified, entries, checkpoints = {}, {}, {}, {}
    for arm in ARMS:
        log = AuditLog()
        admitted[arm] = sum(run_round(arm, r, h, log, i) for i, (r, h) in enumerate(plan))
        verified[arm] = bool(log.verify_full().ok)
        entries[arm] = sum(e["kind"] == "split_verdict" for e in log.entries)
        checkpoints[arm] = sum(e["kind"] == "checkpoint" for e in log.entries)
    return {
        "config": {"rounds": rounds, "k_range": [K_MIN, K_MAX], "fleet_size": FLEET_SIZE, "policy": "default",
                   "max_actions_per_tick": PolicyConfig().max_actions_per_tick, "proposals": total,
                   "runbook_pool": len(pool)},
        "admit_rate_by_arm": {a: admitted[a] / total for a in ARMS},
        "admitted_by_arm": admitted,
        "admit_rate_difference_shared_vs_single": admitted["shared_gate"] / total - admitted["single_actor"] / total,
        "audit_decision_entries_by_arm": entries,
        "audit_checkpoint_entries_by_arm": checkpoints,
        "entries_equal_decisions": {a: entries[a] == total for a in ARMS},
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.split_caller")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.split_caller "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
