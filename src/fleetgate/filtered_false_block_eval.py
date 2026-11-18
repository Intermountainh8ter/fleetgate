"""Benign false-block rate when the proposer only names precondition-passing pairs (SIMULATED).

Same fleet and runbook filter as ``false_block_eval``; pairs with a failed runbook precondition are excluded.
Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .fleet import Fleet
from .policy import Decision, Policy
from .runbooks import CATALOG


def simulate(seed: int, n_benign: int = 1000) -> dict:
    rng = random.Random(seed)
    fleet = Fleet(n=30, seed=seed)
    pol = Policy(fleet)
    rbs = sorted(r for r in CATALOG if r not in pol.cfg.deny_list)
    hosts = sorted(fleet.hosts)
    pairs = [(r, h) for r in rbs for h in hosts
             if not CATALOG[r].failed_preconditions(fleet, h)]
    codes: Counter = Counter()
    denies = 0
    if pairs:
        for _ in range(n_benign):
            v = pol.evaluate(*rng.choice(pairs))
            if v.decision == Decision.DENY:
                denies += 1
                codes[v.code.value] += 1
    return {"filtered_false_block": {
        "n_benign": n_benign, "n_eligible_pairs": len(pairs),
        "n_total_pairs": len(rbs) * len(hosts), "n_deny": denies,
        "deny_rate": denies / n_benign if n_benign else 0.0,
        "by_reason": dict(sorted(codes.items())),
        "n_precondition_failed": codes.get("DENY_PRECONDITION_FAILED", 0),
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.filtered_false_block_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n-benign", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n_benign)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.filtered_false_block_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/abs/2609.01931",
                          "license": "arXiv preprint; used only for the design question, no data taken"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
