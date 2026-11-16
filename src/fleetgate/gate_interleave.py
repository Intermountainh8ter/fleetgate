"""Seeded stale-read interleaving of the real Policy.evaluate against sequential evaluate-then-execute.

Each round, 2..8 simulated agents each propose ``drain_host`` on a distinct validator host. Three arms:
``sequential`` (evaluate, execute, record, next agent), ``stale_read`` (every agent evaluates before any
executes, then all approved drains run) and ``recheck`` (stale evaluation, but each approved drain is
re-evaluated at execute time). A breach is a validator count below the capacity floor or a drained fraction
above the policy maximum after the round. NEEDS_APPROVAL counts as approved (a vote is assumed to pass).
Every verdict lands in an AuditLog whose chain is verified. Simulated data only.
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
from .runbooks import CATALOG

FLEET_SIZE = 40
RUNBOOK = "drain_host"
ARMS = ("sequential", "stale_read", "recheck")


def _approved(v) -> bool:
    return v.decision in (Decision.ALLOW, Decision.NEEDS_APPROVAL)


def _setup(n_validators: int) -> tuple[Fleet, Policy, list[str]]:
    fleet = Fleet(n=FLEET_SIZE, seed=0)
    ids = list(fleet.hosts)
    for h in fleet.hosts.values():
        h.role = "worker"
    for hid in ids[:n_validators]:
        fleet.hosts[hid].role = "validator"
    return fleet, Policy(fleet, PolicyConfig()), ids[:n_validators]


def _breached(fleet: Fleet, cfg: PolicyConfig) -> bool:
    active = sum(1 for h in fleet.hosts.values() if h.role == "validator" and h.active)
    floor = cfg.min_active_per_role["validator"]
    return active < floor or fleet.drained_fraction() > cfg.max_drained_fraction + 1e-12


def _execute(fleet: Fleet, policy: Policy, host_id: str) -> None:
    CATALOG[RUNBOOK].apply(fleet, host_id)
    policy.record(RUNBOOK, host_id)


def run_round(arm: str, n_validators: int, n_agents: int, log: AuditLog, rnd: int) -> dict:
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    fleet, policy, validators = _setup(n_validators)
    targets = validators[:n_agents]
    approved = 0
    if arm == "sequential":
        for agent, hid in enumerate(targets):
            v = policy.evaluate(RUNBOOK, hid)
            log.append("interleave_verdict", arm=arm, round=rnd, agent=agent, code=v.code.value)
            if _approved(v):
                approved += 1
                _execute(fleet, policy, hid)
    else:
        verdicts = []
        for agent, hid in enumerate(targets):  # all evaluate before any executes
            v = policy.evaluate(RUNBOOK, hid)
            log.append("interleave_verdict", arm=arm, round=rnd, agent=agent, code=v.code.value)
            verdicts.append(v)
        for agent, (hid, v) in enumerate(zip(targets, verdicts)):
            if not _approved(v):
                continue
            if arm == "recheck":
                v2 = policy.evaluate(RUNBOOK, hid)
                log.append("interleave_recheck", arm=arm, round=rnd, agent=agent, code=v2.code.value)
                if not _approved(v2):
                    continue
            approved += 1
            _execute(fleet, policy, hid)
    return {"breach": _breached(fleet, policy.cfg), "approved": approved}


def simulate(seed: int, n: int = 500) -> dict:
    rng = random.Random(seed)
    cfg = PolicyConfig()
    rounds = []
    for _ in range(n):
        k = rng.randint(3, 8)
        a = rng.randint(2, 8)
        headroom = min(k - cfg.min_active_per_role["validator"], int(cfg.max_drained_fraction * FLEET_SIZE + 1e-12))
        rounds.append((k, min(a, k), a > headroom))
    over_idx = [i for i, r in enumerate(rounds) if r[2]]
    breaches = {}
    chain_ok = {}
    for arm in ARMS:
        log = AuditLog()
        res = [run_round(arm, k, a, log, i) for i, (k, a, _) in enumerate(rounds)]
        breaches[arm] = res
        chain_ok[arm] = bool(log.verify_full().ok)
    rate = {a: sum(r["breach"] for r in breaches[a]) / n for a in ARMS}
    n_over = max(1, len(over_idx))
    rate_over = {a: sum(breaches[a][i]["breach"] for i in over_idx) / n_over for a in ARMS}
    return {
        "config": {"n_rounds": n, "fleet_size": FLEET_SIZE, "runbook": RUNBOOK, "policy": "default",
                   "rounds_over_headroom": len(over_idx)},
        "real_gate_interleave": {
            "breach_rate": {"stale_read": rate_over["stale_read"], "sequential": rate_over["sequential"],
                            "recheck": rate_over["recheck"]},
            "breach_rate_all_rounds": rate,
            "mean_approved": {a: sum(r["approved"] for r in breaches[a]) / n for a in ARMS},
            "verify_full_ok": chain_ok,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.gate_interleave")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.gate_interleave "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/pdf/2609.00275", "license": "none used; simulated data only"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
