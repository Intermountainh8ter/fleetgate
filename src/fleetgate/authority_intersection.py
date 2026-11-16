"""Seeded delegation-tree authority sweep: a child may hold only what its parent and the policy both allow.

A full tree (fan-out 4, depth 3, 85 agents) over an 8-permission catalogue. The policy allows permissions
0-5 and the root holds 0-3. Each child requests every permission outside its parent's granted set with
probability 0.5 and every parent permission with probability 0.9. Arms: ``union`` (request-as-granted),
``parent_copy`` (child gets exactly the parent's set) and ``intersection`` (request AND parent AND policy).
Out-of-scope = granted permission outside parent-granted AND policy. Excess = granted but not requested.
Every decision lands in an AuditLog whose chain is verified. Simulated data only; wall-clock only in
``provenance``.
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

CATALOGUE = frozenset(range(8))
POLICY = frozenset(range(6))
ROOT = frozenset(range(4))
FANOUT = 4
DEPTH = 3
P_OUTSIDE = 0.5
P_INSIDE = 0.9
ARMS = ("union", "parent_copy", "intersection")


def tree_size() -> int:
    return sum(FANOUT**lvl for lvl in range(DEPTH + 1))


def level_of(i: int) -> int:
    lvl = 0
    while i > 0:
        i = (i - 1) // FANOUT
        lvl += 1
    return lvl


def grant(arm: str, requested: frozenset, parent: frozenset) -> frozenset:
    if arm == "union":
        return requested
    if arm == "parent_copy":
        return parent
    if arm == "intersection":
        return requested & parent & POLICY
    raise ValueError(f"unknown arm {arm!r}")


def run_tree(arm: str, rng: random.Random, log: AuditLog, kind: str, benign: bool) -> dict:
    n = tree_size()
    granted: list[frozenset] = [ROOT]
    out_scope = excess = blocked = 0
    by_level = [0] * (DEPTH + 1)
    for i in range(1, n):
        parent = granted[(i - 1) // FANOUT]
        if benign:
            req = frozenset(p for p in parent & POLICY if rng.random() < P_INSIDE)
        else:
            req = frozenset(p for p in CATALOGUE if rng.random() < (P_INSIDE if p in parent else P_OUTSIDE))
        got = grant(arm, req, parent)
        bad = len(got - (parent & POLICY))
        out_scope += bad
        by_level[level_of(i)] += bad
        excess += len(got - req)
        blocked += benign and got != req
        log.append("authority_verdict", arm=arm, seq_kind=kind, node=i, granted=sorted(got), out_of_scope=bad)
        granted.append(got)
    return {"out_scope": out_scope, "excess": excess, "blocked": blocked, "by_level": by_level}


def simulate(seed: int, rounds: int = 20) -> dict:
    rng = random.Random(seed)
    n = tree_size()
    res: dict[str, dict] = {}
    for arm in ARMS:
        log = AuditLog()
        outs, excs, lvl_max = [], [], [0] * (DEPTH + 1)
        for _ in range(rounds):
            r = run_tree(arm, rng, log, "adversarial", False)
            outs.append(r["out_scope"])
            excs.append(r["excess"])
            lvl_max = [max(a, b) for a, b in zip(lvl_max, r["by_level"])]
        blocked = sum(run_tree(arm, rng, log, "benign", True)["blocked"] for _ in range(rounds))
        res[arm] = {
            "out_of_scope_mean": sum(outs) / rounds,
            "out_of_scope_max_round": max(outs),
            "out_of_scope_max_by_level": lvl_max,
            "excess_mean": sum(excs) / rounds,
            "benign_false_block_rate": blocked / (rounds * (n - 1)),
            "verify_full_ok": bool(log.verify_full().ok),
            "entries_equal_decisions": sum(e["kind"] == "authority_verdict" for e in log.entries)
            == 2 * rounds * (n - 1),
        }
    return {
        "config": {"rounds": rounds, "fanout": FANOUT, "depth": DEPTH, "agents": n,
                   "catalogue": len(CATALOGUE), "policy_allows": len(POLICY), "root_holds": len(ROOT),
                   "p_outside_parent": P_OUTSIDE, "p_inside_parent": P_INSIDE},
        "authority": {
            "out_of_scope_grants_intersection": res["intersection"]["out_of_scope_max_round"],
            "out_of_scope_grants_union_mean": res["union"]["out_of_scope_mean"],
            "out_of_scope_grants_parent_copy": res["parent_copy"]["out_of_scope_max_round"],
            "excess_parent_copy_mean": res["parent_copy"]["excess_mean"],
            "benign_false_block_rate_intersection": res["intersection"]["benign_false_block_rate"],
        },
        "arms": res,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate authority-intersection")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate authority-intersection "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
