"""Seeded delegation-tree revocation sweep: delegation-time grants versus a live intersection at call time.

A full tree (fan-out 4, depth 3, 85 agents) over an 8-permission catalogue. The policy allows permissions
0-5 and the root holds 0-3; every agent was delegated the root's set. At the midpoint round the root revokes
permission 0. Each round every agent makes 10 calls and, per call, attempts each permission it holds with
probability 0.5. Arms: ``cached`` (checks only the delegation-time grant) and ``live`` (re-evaluates the live
root set AND policy AND the agent's grant at call time). Every decision lands in an AuditLog whose chain is
verified. Simulated data only; wall-clock only in ``provenance``.
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

POLICY = frozenset(range(6))
ROOT = frozenset(range(4))
REVOKED = 0
FANOUT = 4
DEPTH = 3
CALLS = 10
P_USE = 0.5
ARMS = ("cached", "live")


def tree_size() -> int:
    return sum(FANOUT**lvl for lvl in range(DEPTH + 1))


def run_arm(arm: str, seed: int, rounds: int) -> dict:
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    rng = random.Random(seed)
    n = tree_size()
    log = AuditLog()
    delegated = ROOT & POLICY
    live_root = set(ROOT)
    revoke_round = rounds // 2
    post_uses = [0] * rounds
    benign_denied = benign_calls = decisions = 0
    for rnd in range(rounds):
        if rnd == revoke_round:
            live_root.discard(REVOKED)
        for agent in range(n):
            for _ in range(CALLS):
                for perm in sorted(delegated):
                    if rng.random() >= P_USE:
                        continue
                    if arm == "cached":
                        allowed = perm in delegated
                    else:
                        allowed = perm in delegated and perm in live_root and perm in POLICY
                    revoked_now = rnd >= revoke_round and perm == REVOKED
                    if revoked_now:
                        post_uses[rnd] += allowed
                    else:
                        benign_calls += 1
                        benign_denied += not allowed
                    decisions += 1
                    log.append("revocation_verdict", arm=arm, round=rnd, agent=agent, perm=perm,
                               allowed=allowed, revoked=revoked_now)
    post = post_uses[revoke_round:]
    return {
        "post_revocation_uses_max_round": max(post),
        "post_revocation_uses_mean_per_round": sum(post) / len(post),
        "post_revocation_uses_total": sum(post),
        "benign_calls": benign_calls,
        "benign_false_deny_rate": benign_denied / benign_calls if benign_calls else 0.0,
        "verify_full_ok": bool(log.verify_full().ok),
        "entries_equal_decisions": sum(e["kind"] == "revocation_verdict" for e in log.entries) == decisions,
    }


def simulate(seed: int, rounds: int = 20) -> dict:
    res = {arm: run_arm(arm, seed, rounds) for arm in ARMS}
    return {
        "config": {"rounds": rounds, "revoke_round": rounds // 2, "fanout": FANOUT, "depth": DEPTH,
                   "agents": tree_size(), "calls_per_agent": CALLS, "p_use": P_USE,
                   "policy_allows": len(POLICY), "root_holds": len(ROOT)},
        "revocation": {
            "post_revocation_uses_live_intersection": res["live"]["post_revocation_uses_max_round"],
            "post_revocation_uses_cached_mean_per_round": res["cached"]["post_revocation_uses_mean_per_round"],
            "benign_false_deny_rate_live": res["live"]["benign_false_deny_rate"],
        },
        "arms": res,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate grant-revocation")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate grant-revocation "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
