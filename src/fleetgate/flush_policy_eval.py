"""Durable-flush policies for the audit log under a multi-agent decision stream, with crash truncation.

Policies: ``per_append`` (flush after every append), ``every_32`` (flush after every 32nd append) and
``group_commit`` (one flush at the end of each tick that had appends). Flushes are counted, not timed. A crash
keeps the entries covered by the last flush; ``verify_full`` is run on a seeded sample of the truncated logs to
see whether the chain alone notices the loss. Simulated data only.
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
from typing import Any

from .audit import AuditLog

POLICIES = ("per_append", "every_32", "group_commit")
FLEETS = (1, 8, 64, 512)
APPEND_P = 0.5
VERIFY_SAMPLE = 20


def make_ticks(seed: int, agents: int, ticks: int) -> list[int]:
    """Appends per tick."""
    rng = random.Random(seed * 1000 + agents)
    return [sum(1 for _ in range(agents) if rng.random() < APPEND_P) for _ in range(ticks)]


def flush_points(policy: str, per_tick: list[int]) -> list[int]:
    """Cumulative append counts after which a flush happens."""
    points: list[int] = []
    total = 0
    for n in per_tick:
        for _ in range(n):
            total += 1
            if policy == "per_append" or (policy == "every_32" and total % 32 == 0):
                points.append(total)
        if policy == "group_commit" and n:
            points.append(total)
    return points


def durable_at(points: list[int], k: int) -> int:
    best = 0
    for p in points:
        if p > k:
            break
        best = p
    return best


def _log(n: int) -> AuditLog:
    log = AuditLog(checkpoint_every=0)
    for i in range(n):
        log.append("agent_record", agent=i % 7, units=i % 10)
    return log


def run_cell(seed: int, agents: int, ticks: int, crashes: int, policy: str) -> dict[str, Any]:
    per_tick = make_ticks(seed, agents, ticks)
    decisions = sum(per_tick)
    points = flush_points(policy, per_tick)
    rng = random.Random(seed * 7 + agents * 3 + POLICIES.index(policy))
    ks = [rng.randint(0, decisions) for _ in range(crashes)]
    lost = [k - durable_at(points, k) for k in ks]
    full = _log(decisions)
    sample = [i for i in range(crashes) if lost[i] > 0]
    sample = rng.sample(sample, min(VERIFY_SAMPLE, len(sample)))
    detected = 0
    for i in sample:
        trunc = AuditLog(checkpoint_every=0)
        trunc.entries = full.entries[: ks[i] - lost[i]]
        if not trunc.verify_full().ok:
            detected += 1
    return {"decisions": decisions, "flushes": len(points), "flush_calls_per_decision": len(points) / decisions,
            "mean_entries_lost": sum(lost) / crashes, "max_entries_lost": max(lost),
            "crashes_with_loss": sum(1 for x in lost if x > 0), "n_verified": len(sample),
            "n_detected_by_verify_full": detected,
            "chain_only_detection_share": (detected / len(sample)) if sample else None}


def simulate(seed: int, ticks: int, crashes: int, fleets: tuple[int, ...] = FLEETS) -> dict[str, Any]:
    cells = {str(a): {p: run_cell(seed, a, ticks, crashes, p) for p in POLICIES} for a in fleets}
    big = str(fleets[-1])
    verified = [c for f in cells.values() for c in f.values() if c["n_verified"]]
    detected = sum(c["n_detected_by_verify_full"] for c in verified)
    n_ver = sum(c["n_verified"] for c in verified)
    return {
        "fleets": list(fleets), "ticks": ticks, "crashes": crashes, "append_probability": APPEND_P,
        "cells": cells,
        "flush_calls_per_decision": {
            "per_append_largest_fleet": cells[big]["per_append"]["flush_calls_per_decision"],
            "every_32_largest_fleet": cells[big]["every_32"]["flush_calls_per_decision"],
            "group_commit_largest_fleet": cells[big]["group_commit"]["flush_calls_per_decision"]},
        "truncation": {"n_verified": n_ver, "n_detected_by_verify_full": detected,
                       "chain_only_detection_share": (detected / n_ver) if n_ver else None},
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.flush_policy_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--ticks", type=int, default=400)
    ap.add_argument("--crashes", type=int, default=2000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.ticks, args.crashes)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.flush_policy_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: fleetgate seeded multi-agent decision stream",
                          "license": "MIT (repo-internal synthetic data)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
