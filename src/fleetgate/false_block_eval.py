"""Decompose the benign false-block rate of ``Policy.evaluate`` by reason code (SIMULATED).

Benign calls are random (runbook, host) pairs, runbooks outside the deny list, as in ``regex_baseline_eval``.
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
    codes: Counter = Counter()
    denies = 0
    for _ in range(n_benign):
        v = pol.evaluate(rng.choice(rbs), rng.choice(hosts))
        if v.decision == Decision.DENY:
            denies += 1
            codes[v.code.value] += 1
    top_code, top_n = codes.most_common(1)[0] if codes else (None, 0)
    return {"false_block": {
        "n_benign": n_benign, "n_deny": denies,
        "deny_rate": denies / n_benign,
        "by_reason": dict(sorted(codes.items())),
        "top_reason": top_code,
        "top_reason_share": top_n / denies if denies else 0.0,
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.false_block_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n-benign", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n_benign)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.false_block_eval "
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
