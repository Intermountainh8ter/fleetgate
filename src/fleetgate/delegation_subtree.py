"""Seeded delegation-subtree sweep: agents spawn children that each spend inside their own quota.

Units are integer milli-units. Every node of a full tree (fan-out ``f``, depth ``d``) requests the per-agent
quota against one root-principal limit. Arms: ``per_agent_rule`` (quota check only), ``depth_capped_rule``
(quota check, nodes deeper than ``DEPTH_CAP`` denied) and ``subtree_rule`` (quota check plus an atomic running
total keyed on the root). Every decision lands in an AuditLog whose chain is verified. Simulated data only;
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
DEPTH_CAP = 2
DEPTHS = (1, 2, 3)
FANOUTS = (2, 4)
ARMS = ("per_agent_rule", "depth_capped_rule", "subtree_rule")


def tree_depths(fanout: int, depth: int) -> list[int]:
    """Node depths in breadth-first order for a full tree; the root has depth 0."""
    return [lvl for lvl in range(depth + 1) for _ in range(fanout**lvl)]


def admit(arm: str, requests: list[tuple[int, int]], log: AuditLog, kind: str, fanout: int, depth: int) -> list[int]:
    """Process (node depth, units) requests in order; return the admitted amounts."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    total = 0
    admitted: list[int] = []
    for node, (lvl, units) in enumerate(requests):
        ok, code = units <= QUOTA, "ALLOW"
        if not ok:
            code = "DENY_AGENT_QUOTA"
        elif arm == "depth_capped_rule" and lvl > DEPTH_CAP:
            ok, code = False, "DENY_DEPTH_CAP"
        elif arm == "subtree_rule" and total + units > ROOT_LIMIT:
            ok, code = False, "DENY_SUBTREE_LIMIT"
        log.append("delegation_subtree_verdict", arm=arm, seq_kind=kind, fanout=fanout, depth=depth,
                   node=node, code=code)
        if ok:
            total += units
            admitted.append(units)
    return admitted


def simulate(seed: int, rounds: int = 20) -> dict:
    rng = random.Random(seed)
    ratio: dict[str, dict[str, float]] = {a: {} for a in ARMS}
    benign_block: dict[str, float] = dict.fromkeys(ARMS, 0.0)
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    for arm in ARMS:
        log = AuditLog()
        decisions = blocked = total_benign = 0
        for fanout in FANOUTS:
            for depth in DEPTHS:
                lvls = tree_depths(fanout, depth)
                n = len(lvls)
                ratios = []
                for _ in range(rounds):
                    got = admit(arm, [(lv, QUOTA) for lv in lvls], log, "colluding", fanout, depth)
                    ratios.append(sum(got) / ROOT_LIMIT)
                    decisions += n
                ratio[arm][f"fanout{fanout}_depth{depth}"] = sum(ratios) / rounds
                for _ in range(rounds):
                    share = min(QUOTA, ROOT_LIMIT // n)
                    req = [(lv, share - rng.randint(0, 1)) for lv in lvls]  # joint demand never above the limit
                    if arm == "depth_capped_rule":
                        # benign trees stay within the cap, so only count trees the cap would allow
                        req = [(min(lv, DEPTH_CAP), u) for lv, u in req]
                    got = admit(arm, req, log, "benign", fanout, depth)
                    blocked += len(got) < n
                    total_benign += 1
                    decisions += n
        benign_block[arm] = blocked / total_benign
        verified[arm] = bool(log.verify_full().ok)
        entries_ok[arm] = sum(e["kind"] == "delegation_subtree_verdict" for e in log.entries) == decisions
    return {
        "config": {"rounds": rounds, "depths": list(DEPTHS), "fanouts": list(FANOUTS), "depth_cap": DEPTH_CAP,
                   "per_agent_quota_units": QUOTA // UNIT, "root_limit_units": ROOT_LIMIT // UNIT},
        "delegation_subtree": {
            "depth_capped_overdraw_ratio_fanout4_cap2": ratio["depth_capped_rule"]["fanout4_depth3"],
            "per_agent_overdraw_ratio_fanout4_depth3": ratio["per_agent_rule"]["fanout4_depth3"],
            "subtree_overdraw_ratio_max": max(ratio["subtree_rule"].values()),
            "overdraw_ratio_by_tree": ratio,
            "benign_false_block_rate": benign_block,
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate delegation-subtree")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate delegation-subtree " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
