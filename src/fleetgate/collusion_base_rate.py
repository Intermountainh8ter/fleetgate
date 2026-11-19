"""Seeded base-rate sweep of split-action colluders mixed into benign traffic.

Each sequence is a colluding composite (8 reversible steps on one rack, budget ``RACK_BUDGET`` = 4) with
probability equal to the base rate, otherwise a benign sequence of equal length over two racks. Arms reuse
``split_action.run_sequence``: the per-action ``default_policy`` and the ``cumulative_rule``. Simulated data
only; no wall-clock field outside ``provenance``.
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
from .split_action import RACK_BUDGET, run_sequence
from .split_caller import _fleet, admissible_runbooks

BASE_RATES = (0.01, 0.05, 0.20, 0.50)
DEPTH = 8
ARMS = ("default_policy", "cumulative_rule")


def _sequence(rng: random.Random, pool, racks, colluder: bool):
    a, b = rng.sample(racks, 2)
    if colluder:
        return list(zip(rng.sample(pool, DEPTH), rng.sample(a.hosts, DEPTH)))
    hosts = rng.sample(a.hosts, RACK_BUDGET) + rng.sample(b.hosts, RACK_BUDGET)
    rng.shuffle(hosts)
    return list(zip(rng.sample(pool, len(hosts)), hosts))


def simulate(seed: int, n_sequences: int = 2000) -> dict:
    rng = random.Random(seed)
    pool = admissible_runbooks()
    racks = [r for r in _fleet().topology.racks.values() if len(r.hosts) >= DEPTH]
    if len(pool) < DEPTH or len(racks) < 2:
        raise RuntimeError("not enough admissible runbooks or racks")
    out: dict = {}
    verified = True
    for rate in BASE_RATES:
        plan = []
        for _ in range(n_sequences):
            col = rng.random() < rate
            plan.append((col, _sequence(rng, pool, racks, col)))
        n_col = sum(c for c, _ in plan)
        n_ben = n_sequences - n_col
        clear: dict[str, int] = {}
        benign_blocked: dict[str, int] = {}
        for arm in ARMS:
            log = AuditLog()
            c = bb = 0
            for i, (col, steps) in enumerate(plan):
                ok = run_sequence(arm, steps, log, i, "composite" if col else "benign") == len(steps)
                if col and ok:
                    c += 1
                if not col and not ok:
                    bb += 1
            verified = verified and bool(log.verify_full().ok)
            clear[arm], benign_blocked[arm] = c, bb
        key = f"{rate:g}" if rate != 0.20 else "0.2"
        out[key] = {
            "n_colluders": n_col, "n_benign": n_ben,
            "default_policy_clear_rate": clear["default_policy"] / n_col if n_col else None,
            "cumulative_rule_clear_rate": clear["cumulative_rule"] / n_col if n_col else None,
            "default_policy_benign_false_block_rate": benign_blocked["default_policy"] / n_ben if n_ben else None,
            "cumulative_rule_benign_false_block_rate": benign_blocked["cumulative_rule"] / n_ben if n_ben else None,
            "cumulative_rule_precision": (n_col - clear["cumulative_rule"])
            / (n_col - clear["cumulative_rule"] + benign_blocked["cumulative_rule"])
            if (n_col - clear["cumulative_rule"] + benign_blocked["cumulative_rule"]) else None,
        }
    res = {f"default_policy_clear_rate_at_{k}": v["default_policy_clear_rate"] for k, v in out.items()}
    res.update({f"cumulative_rule_false_block_rate_at_{k}": v["cumulative_rule_benign_false_block_rate"]
                for k, v in out.items()})
    res.update({"by_base_rate": out, "verify_full_ok": verified})
    return {"config": {"n_sequences": n_sequences, "base_rates": list(BASE_RATES), "depth": DEPTH,
                       "rack_budget": RACK_BUDGET, "runbook_pool": len(pool)},
            "collusion_base_rate": res}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate collusion-base-rate")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n-sequences", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n_sequences)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "python3 -m fleetgate.collusion_base_rate " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
