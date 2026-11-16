"""Seeded sibling-subtree collusion sweep: each subtree stays inside its own cap, the trio overdraws the root.

Units are integer milli-units. ``SUBTREES`` full trees (fan-out 4, depth 2) hang under one root limit. Every
agent requests the per-agent quota. Arms: ``per_agent_only`` (quota check), ``per_subtree`` (quota check plus
an atomic total per subtree capped at ``SUBTREE_CAP``) and ``root_atomic`` (quota check plus an atomic total
keyed on the root). Every decision lands in an AuditLog whose chain is verified. Simulated data only;
wall-clock only in ``provenance``.
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

UNIT = 1000
QUOTA = 10 * UNIT
ROOT_LIMIT = 100 * UNIT
SUBTREE_CAP = 50 * UNIT
SUBTREES = 3
FANOUT = 4
DEPTH = 2
ARMS = ("per_agent_only", "per_subtree", "root_atomic")


def subtree_size() -> int:
    return sum(FANOUT**lvl for lvl in range(DEPTH + 1))


def admit(arm: str, requests: list[tuple[int, int]], log: AuditLog, kind: str) -> list[int]:
    """Process (subtree, units) requests in order; return the admitted amounts."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    root_total = 0
    per_tree = [0] * SUBTREES
    admitted: list[int] = []
    for node, (tree, units) in enumerate(requests):
        ok, code = units <= QUOTA, "ALLOW"
        if not ok:
            code = "DENY_AGENT_QUOTA"
        elif arm == "per_subtree" and per_tree[tree] + units > SUBTREE_CAP:
            ok, code = False, "DENY_SUBTREE_CAP"
        elif arm == "root_atomic" and root_total + units > ROOT_LIMIT:
            ok, code = False, "DENY_ROOT_LIMIT"
        log.append("subtree_collusion_verdict", arm=arm, seq_kind=kind, node=node, subtree=tree, code=code)
        if ok:
            root_total += units
            per_tree[tree] += units
            admitted.append(units)
    return admitted


def simulate(seed: int, rounds: int = 20) -> dict:
    rng = random.Random(seed)
    n = subtree_size()
    ratio: dict[str, float] = {}
    breaches: dict[str, int] = {}
    benign_block: dict[str, float] = {}
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    for arm in ARMS:
        log = AuditLog()
        decisions = blocked = 0
        ratios = []
        for _ in range(rounds):
            got = admit(arm, [(t, QUOTA) for t in range(SUBTREES) for _ in range(n)], log, "colluding")
            ratios.append(sum(got) / ROOT_LIMIT)
            decisions += SUBTREES * n
        ratio[arm] = sum(ratios) / rounds
        breaches[arm] = sum(r > 1.0 for r in ratios)
        for _ in range(rounds):
            # joint demand 80 units: 80_000 milli-units split across all agents, jittered down only
            share = 80 * UNIT // (SUBTREES * n)
            req = [(t, share - rng.randint(0, 1)) for t in range(SUBTREES) for _ in range(n)]
            got = admit(arm, req, log, "benign")
            blocked += len(got) < len(req)
            decisions += len(req)
        benign_block[arm] = blocked / rounds
        verified[arm] = bool(log.verify_full().ok)
        entries_ok[arm] = sum(e["kind"] == "subtree_collusion_verdict" for e in log.entries) == decisions
    return {
        "config": {"rounds": rounds, "subtrees": SUBTREES, "fanout": FANOUT, "depth": DEPTH,
                   "agents_per_subtree": n, "per_agent_quota_units": QUOTA // UNIT,
                   "subtree_cap_units": SUBTREE_CAP // UNIT, "root_limit_units": ROOT_LIMIT // UNIT},
        "subtree_collusion": {
            "breaches_root_atomic": breaches["root_atomic"],
            "breaches_per_subtree": breaches["per_subtree"],
            "breaches_per_agent_only": breaches["per_agent_only"],
            "overdraw_ratio_root_atomic": ratio["root_atomic"],
            "overdraw_ratio_per_subtree": ratio["per_subtree"],
            "overdraw_ratio_per_agent_only": ratio["per_agent_only"],
            "benign_false_block_rate": benign_block,
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate subtree-collusion")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate subtree-collusion " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
