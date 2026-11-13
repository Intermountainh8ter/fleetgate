"""Seeded simulation of colluding agents that each stay under a per-call cap but jointly exceed a fleet budget.

Three gate arms are compared on the share of jointly violating sequences they pass:
``per_call_gate`` (cap only), ``check_then_act_gate`` (aggregate check on a stale read, adversarial interleaving:
every agent in a round reads before any of them writes) and ``atomic_gate`` (check and reserve in one step).
Every decision lands in an AuditLog whose chain is verified after each arm. Simulated data only.
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

N_AGENTS = 8
PER_CALL_CAP = 10
FLEET_BUDGET = 100
ARMS = ("per_call_gate", "check_then_act_gate", "atomic_gate")


def make_sequence(rng: random.Random, n_agents: int = N_AGENTS, cap: int = PER_CALL_CAP,
                  budget: int = FLEET_BUDGET) -> list[list[int]]:
    """Per-agent lists of action sizes, each in 1..cap, resampled until total demand exceeds the budget."""
    while True:
        seq = [[rng.randint(1, cap) for _ in range(rng.randint(3, 6))] for _ in range(n_agents)]
        if sum(map(sum, seq)) > budget:
            return seq


def run_arm(arm: str, seq: list[list[int]], log: AuditLog, cap: int = PER_CALL_CAP,
            budget: int = FLEET_BUDGET) -> int:
    """Run one sequence through one gate arm; return total units admitted."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    spent = 0
    for rnd in range(max(map(len, seq))):
        acts = [(a, s[rnd]) for a, s in enumerate(seq) if rnd < len(s)]
        reads = {a: spent for a, _ in acts}  # every agent reads before any writes
        for agent, units in acts:
            if units > cap:
                ok = False
            elif arm == "per_call_gate":
                ok = True
            elif arm == "check_then_act_gate":
                ok = reads[agent] + units <= budget
            else:
                ok = spent + units <= budget
            if ok:
                spent += units
            log.append("collusion_verdict", arm=arm, agent=agent, round=rnd, units=units,
                       verdict="ALLOW" if ok else "DENY", spent=spent)
    return spent


def simulate(seed: int, n_sequences: int = 1000) -> dict:
    rng = random.Random(seed)
    seqs = [make_sequence(rng) for _ in range(n_sequences)]
    passed = dict.fromkeys(ARMS, 0)
    overshoot = dict.fromkeys(ARMS, 0)
    chain_ok = {}
    for arm in ARMS:
        log = AuditLog()
        for seq in seqs:
            spent = run_arm(arm, seq, log)
            if spent > FLEET_BUDGET:
                passed[arm] += 1
                overshoot[arm] += spent - FLEET_BUDGET
        chain_ok[arm] = bool(log.verify_full().ok)
    n = len(seqs)
    return {
        "config": {"n_agents": N_AGENTS, "per_call_cap": PER_CALL_CAP, "fleet_budget": FLEET_BUDGET,
                   "n_sequences": n, "all_sequences_violate_in_aggregate": True},
        "collusion": {
            "pass_through_rate": {a: passed[a] / n for a in ARMS},
            "mean_overshoot_units": {a: overshoot[a] / n for a in ARMS},
            "violating_sequences_passed": passed,
            "audit_chain_verified": chain_ok,
            "audit_entries_per_arm": sum(len(s) for q in seqs for s in q),
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    res = simulate(args.seed, args.n)
    res["provenance"] = {
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.collusion "
                   + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.monotonic() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/pdf/2609.00275", "license": "none used; simulated data only"}],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
