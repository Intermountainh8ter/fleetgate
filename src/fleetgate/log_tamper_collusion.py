"""Seeded log-tamper sweep: colluding subtrees overdraw the root, then rewrite their own log.

The ``per_subtree`` arm of ``subtree_collusion`` admits 150 units against a root limit of 100. The colluder deletes
the ALLOW entries after the root limit was crossed and rebuilds the chain (rehashed, no HMAC key). Two verifiers
look at the result: hash-chain-only (``verify_full`` plus replay of cumulative ALLOW units) and anchored
(``verify_full`` with the checkpoint roots captured by a MemoryAnchor during the original write, plus replay).
An untampered benign log and an untampered breaching log are controls. Simulated data only; wall-clock only in
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

from .audit import AuditLog, MemoryAnchor
from .subtree_collusion import QUOTA, ROOT_LIMIT, SUBTREES, UNIT, admit, subtree_size

KIND = "subtree_collusion_verdict"
CHECKPOINT_EVERY = 16


def _sizes(requests: list[tuple[int, int]]) -> dict[int, int]:
    return {i: u for i, (_, u) in enumerate(requests)}


def write_log(requests: list[tuple[int, int]], kind: str) -> tuple[AuditLog, MemoryAnchor]:
    anchor = MemoryAnchor()
    log = AuditLog(checkpoint_every=CHECKPOINT_EVERY, anchor=anchor)
    admit("per_subtree", requests, log, kind)
    return log, anchor


def allowed_units(log: AuditLog, requests: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """(seq, units) of every ALLOW verdict, units looked up from the request list by node."""
    units = _sizes(requests)
    return [(e["seq"], units[e["node"]]) for e in log.of_kind(KIND) if e["code"] == "ALLOW"]


def replay_breach(log: AuditLog, requests: list[tuple[int, int]]) -> bool:
    """True when cumulative ALLOW units in the log exceed the root limit."""
    return sum(u for _, u in allowed_units(log, requests)) > ROOT_LIMIT


def conceal(log: AuditLog, requests: list[tuple[int, int]]) -> tuple[AuditLog, list[int]]:
    """Delete ALLOW entries evidencing the overdraw and rebuild a valid unsigned chain."""
    total, victims = 0, []
    for seq, u in allowed_units(log, requests):
        total += u
        if total > ROOT_LIMIT:
            victims.append(seq)
    rebuilt = AuditLog(checkpoint_every=CHECKPOINT_EVERY)
    for e in log.entries:
        if e["kind"] == KIND and e["seq"] not in victims:
            body = {k: v for k, v in e.items() if k not in ("seq", "kind", "prev", "hash", "sig")}
            rebuilt.append(KIND, **body)
    return rebuilt, victims


def flagged(log: AuditLog, requests: list[tuple[int, int]], anchors: dict[int, str] | None) -> bool:
    if not log.verify_full(anchors=anchors).ok:
        return True
    return replay_breach(log, requests)


def simulate(seed: int, rounds: int = 20) -> dict:
    rng = random.Random(seed)
    n = subtree_size()
    breaching = [(t, QUOTA) for t in range(SUBTREES) for _ in range(n)]
    chain_missed = anchored_missed = control_caught = deleted = 0
    benign_chain = benign_anchored = 0
    for _ in range(rounds):
        log, anchor = write_log(breaching, "colluding")
        control_caught += flagged(log, breaching, anchor.roots)
        tampered, victims = conceal(log, breaching)
        deleted += len(victims)
        chain_missed += not flagged(tampered, breaching, None)
        anchored_missed += not flagged(tampered, breaching, anchor.roots)
        share = 80 * UNIT // (SUBTREES * n)
        benign = [(t, share - rng.randint(0, 1)) for t in range(SUBTREES) for _ in range(n)]
        blog, banchor = write_log(benign, "benign")
        benign_chain += flagged(blog, benign, None)
        benign_anchored += flagged(blog, benign, banchor.roots)
    return {
        "config": {"rounds": rounds, "subtrees": SUBTREES, "agents_per_subtree": n,
                   "root_limit_units": ROOT_LIMIT // UNIT, "checkpoint_every": CHECKPOINT_EVERY},
        "tamper": {
            "undetected_breaches_writable_log": chain_missed / rounds,
            "undetected_breaches_anchored": anchored_missed / rounds,
            "untampered_breach_detected_rate": control_caught / rounds,
            "benign_false_flag_chain_only": benign_chain,
            "benign_false_flag_anchored": benign_anchored,
            "mean_entries_deleted": deleted / rounds,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate log-tamper-collusion")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate log-tamper-collusion " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
