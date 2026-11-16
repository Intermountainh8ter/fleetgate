"""Seeded split-action rounds against the real Policy.evaluate/record.

A composite action (more reversible restarts across one rack than the cumulative budget of ``RACK_BUDGET``)
is split into one allowed sub-step per tick, each a different runbook on a distinct host so no canary campaign
forms. Arms: ``default_policy`` (per-action gate), ``cumulative_rule`` (the same gate plus a per-rack effect
count kept across ticks) and ``quota_per_role`` (the gate with a role quota equal to the budget). Benign
sequences of equal length spread over two racks, staying at the budget per rack. Every verdict lands in an
AuditLog whose chain is verified. Simulated data only; no wall-clock field outside ``provenance``.
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
from .split_caller import _fleet, admissible_runbooks

RACK_BUDGET = 4
DEPTHS = tuple(range(1, 9))
ARMS = ("default_policy", "cumulative_rule", "quota_per_role")


def _policy(arm: str, fleet) -> Policy:
    cfg = PolicyConfig()
    if arm == "quota_per_role":
        cfg.quotas = {**cfg.quotas, "per_role": {"worker": RACK_BUDGET}}
    return Policy(fleet, cfg)


def run_sequence(arm: str, steps: list[tuple[str, str]], log: AuditLog, rnd: int, kind: str) -> int:
    """Propose one (runbook, host) step per tick; return the number of admitted steps."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    fleet = _fleet()
    policy = _policy(arm, fleet)
    per_rack: dict[str, int] = {}
    admitted = 0
    for rid, hid in steps:
        fleet.tick += 1
        rack = fleet.topology.rack_of(hid).id
        v = policy.evaluate(rid, hid)
        code = v.code.value
        ok = v.decision == Decision.ALLOW
        if ok and arm == "cumulative_rule" and per_rack.get(rack, 0) >= RACK_BUDGET:
            ok, code = False, "CUMULATIVE_RACK_BUDGET"
        log.append("split_action_verdict", arm=arm, seq_kind=kind, round=rnd, rack=rack, code=code)
        if ok:
            admitted += 1
            per_rack[rack] = per_rack.get(rack, 0) + 1
            policy.record(rid, hid)
    return admitted


def simulate(seed: int, rounds: int = 200) -> dict:
    rng = random.Random(seed)
    pool = admissible_runbooks()
    if len(pool) < max(DEPTHS):
        raise RuntimeError("not enough admissible reversible runbooks")
    topo = _fleet().topology
    racks = [r for r in topo.racks.values() if len(r.hosts) >= max(DEPTHS)]
    if len(racks) < 2:
        raise RuntimeError("need two racks with enough hosts")
    plan = []
    for _ in range(rounds):
        a, b = rng.sample(racks, 2)
        comp = {d: list(zip(rng.sample(pool, d), rng.sample(a.hosts, d))) for d in DEPTHS}
        hosts = rng.sample(a.hosts, RACK_BUDGET) + rng.sample(b.hosts, RACK_BUDGET)
        rng.shuffle(hosts)
        benign = list(zip(rng.sample(pool, len(hosts)), hosts))
        plan.append((comp, benign))
    by_depth: dict[str, dict[str, float]] = {a: {} for a in ARMS}
    benign_block: dict[str, float] = {}
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    for arm in ARMS:
        log = AuditLog()
        decisions = 0
        for d in DEPTHS:
            full = sum(run_sequence(arm, comp[d], log, i, f"composite{d}") == d for i, (comp, _) in enumerate(plan))
            by_depth[arm][str(d)] = full / rounds
            decisions += d * rounds
        blocked = sum(run_sequence(arm, ben, log, i, "benign") < len(ben) for i, (_, ben) in enumerate(plan))
        benign_block[arm] = blocked / rounds
        decisions += 2 * RACK_BUDGET * rounds
        verified[arm] = bool(log.verify_full().ok)
        entries_ok[arm] = sum(e["kind"] == "split_action_verdict" for e in log.entries) == decisions
    deepest = str(max(DEPTHS))
    return {
        "config": {"rounds": rounds, "depths": list(DEPTHS), "rack_budget": RACK_BUDGET, "policy": "default",
                   "max_actions_per_tick": PolicyConfig().max_actions_per_tick, "runbook_pool": len(pool)},
        "collusion": {
            "default_policy_composite_admit_rate_depth8": by_depth["default_policy"][deepest],
            "cumulative_rule_composite_admit_rate_depth8": by_depth["cumulative_rule"][deepest],
            "quota_per_role_composite_admit_rate_depth8": by_depth["quota_per_role"][deepest],
            "benign_false_block_rate_default_policy": benign_block["default_policy"],
            "benign_false_block_rate_cumulative_rule": benign_block["cumulative_rule"],
            "benign_false_block_rate_quota_per_role": benign_block["quota_per_role"],
            "composite_admit_rate_by_depth": by_depth,
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate split-action")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate split-action " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
