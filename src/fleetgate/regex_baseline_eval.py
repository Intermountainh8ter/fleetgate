"""Regex deny-list baseline versus ``Policy.evaluate`` on mutated harmful calls and matched benign calls (SIMULATED).

The regex gate is a case-sensitive pattern built from the deny-listed runbook names, applied to the string form of
each argument. It "blocks" a call on a match; the policy gate blocks on DENY. Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .fleet import Fleet
from .mutation_eval import CLASSES, KINDS, _canonical, mutate, wilson
from .policy import Decision, Policy
from .runbooks import CATALOG


def build_regex(deny_list) -> re.Pattern:
    return re.compile("|".join(re.escape(r) for r in sorted(deny_list)))


def regex_blocks(pat: re.Pattern, runbook, host) -> bool:
    return bool(pat.search(str(runbook)) or pat.search(str(host)))


def simulate(seed: int, n: int = 480, n_benign: int = 200) -> dict:
    rng = random.Random(seed)
    fleet = Fleet(n=30, seed=seed)
    pol = Policy(fleet)
    pat = build_regex(pol.cfg.deny_list)
    host = sorted(fleet.hosts)[0]
    per = n // len(CLASSES)
    gate_b = regex_b = total = 0
    by_class = {c: {"n": 0, "gate": 0, "regex": 0} for c in CLASSES}
    by_kind = {k: {"n": 0, "gate": 0, "regex": 0} for k in KINDS}
    for cls in CLASSES:
        for i in range(per):
            kind = KINDS[i % len(KINDS)]
            args = list(_canonical(kind, host)[:2])
            idx = _canonical(kind, host)[2]
            args[idx] = mutate(cls, args[idx], rng)
            g = pol.evaluate(*args).decision == Decision.DENY
            r = regex_blocks(pat, *args)
            for d in (by_class[cls], by_kind[kind]):
                d["n"] += 1
                d["gate"] += g
                d["regex"] += r
            total += 1
            gate_b += g
            regex_b += r
    rbs = sorted(r for r in CATALOG if not pat.search(r))
    hosts = sorted(fleet.hosts)
    bg = br = 0
    for _ in range(n_benign):
        rb, h = rng.choice(rbs), rng.choice(hosts)
        bg += pol.evaluate(rb, h).decision == Decision.DENY
        br += regex_blocks(pat, rb, h)
    gate_rate, regex_rate = gate_b / total, regex_b / total
    return {"gate": {
        "n_harmful": total, "n_benign": n_benign,
        "block_rate": gate_rate, "regex_block_rate": regex_rate,
        "block_rate_delta_vs_regex": gate_rate - regex_rate,
        "regex_wilson95": list(wilson(regex_b, total)),
        "false_block_rate": bg / n_benign, "regex_false_block_rate": br / n_benign,
        "by_class": by_class, "by_kind": by_kind,
        "regex_pattern_is_case_sensitive": True,
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.regex_baseline_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=480)
    ap.add_argument("--n-benign", type=int, default=200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n, args.n_benign)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.regex_baseline_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/abs/2609.35659v1",
                          "license": "arXiv preprint; used only for the design question, no data taken"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
