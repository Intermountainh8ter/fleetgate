"""Seeded gate-restart campaigns against the real Policy.evaluate/record.

Each round is a fleet-wide campaign: 6..9 proposals of one reversible, non-draining runbook on distinct hosts of a
40-host fleet, one proposal per tick, no verification feedback. Arms: ``persistent`` (one Policy), ``restart_each``
(a fresh Policy before every proposal), ``state_carry`` (a fresh Policy that copies campaigns, recent, history and
actions_this_tick) and ``config_swap`` (the same Policy with cfg replaced by an equal PolicyConfig). An ALLOW
verdict is recorded as executed. Every verdict lands in an AuditLog whose chain is verified, one decision entry
per verdict. Simulated data only.
"""
from __future__ import annotations

import argparse
import copy
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
from .split_caller import FLEET_SIZE, _fleet, admissible_runbooks

K_MIN, K_MAX = 6, 9
ARMS = ("persistent", "restart_each", "state_carry", "config_swap")


def _carry(old: Policy, fleet: Fleet) -> Policy:
    new = Policy(fleet, PolicyConfig())
    new.campaigns = copy.deepcopy(old.campaigns)
    new.recent = dict(old.recent)
    new.history = list(old.history)
    new.actions_this_tick = dict(old.actions_this_tick)
    return new


def run_round(arm: str, runbook: str, hosts: list[str], log: AuditLog, rnd: int) -> int:
    """Return the number of admitted proposals."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    fleet = _fleet()
    policy = Policy(fleet, PolicyConfig())
    admitted = 0
    for i, hid in enumerate(hosts):
        fleet.tick = i
        if arm == "restart_each":
            policy = Policy(fleet, PolicyConfig())
        elif arm == "state_carry":
            policy = _carry(policy, fleet)
        elif arm == "config_swap":
            policy.cfg = PolicyConfig()
        v = policy.evaluate(runbook, hid)
        log.append("restart_verdict", arm=arm, round=rnd, step=i, code=v.code.value)
        if v.decision == Decision.ALLOW:
            admitted += 1
            policy.record(runbook, hid)
    return admitted


def simulate(seed: int, rounds: int = 1000) -> dict:
    rng = random.Random(seed)
    pool = admissible_runbooks()
    host_ids = list(_fleet().hosts)
    plan = []
    for _ in range(rounds):
        k = rng.randint(K_MIN, K_MAX)
        plan.append((rng.choice(pool), rng.sample(host_ids, k)))
    total = sum(len(p[1]) for p in plan)
    admitted, verified, entries, checkpoints = {}, {}, {}, {}
    max_round_rate = {}
    for arm in ARMS:
        log = AuditLog()
        per = [run_round(arm, r, h, log, i) for i, (r, h) in enumerate(plan)]
        admitted[arm] = sum(per)
        max_round_rate[arm] = max(a / len(h) for a, (_, h) in zip(per, plan))
        verified[arm] = bool(log.verify_full().ok)
        entries[arm] = sum(e["kind"] == "restart_verdict" for e in log.entries)
        checkpoints[arm] = sum(e["kind"] == "checkpoint" for e in log.entries)
    return {
        "config": {"rounds": rounds, "k_range": [K_MIN, K_MAX], "fleet_size": FLEET_SIZE, "policy": "default",
                   "proposals": total, "runbook_pool": len(pool)},
        "admit_rate_by_arm": {a: admitted[a] / total for a in ARMS},
        "admitted_by_arm": admitted,
        "max_round_admit_rate_by_arm": max_round_rate,
        "admit_count_difference_vs_persistent": {a: admitted[a] - admitted["persistent"] for a in ARMS},
        "audit_decision_entries_by_arm": entries,
        "audit_checkpoint_entries_by_arm": checkpoints,
        "entries_equal_decisions": {a: entries[a] == total for a in ARMS},
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.gate_restart")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.gate_restart "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
