"""Seeded fleet-overdraw sweep: N agents, each inside its own per-agent quota, against one fleet limit.

Units are integer milli-units (``UNIT`` per unit). Colluding agents each request exactly the per-agent quota;
benign fleets split a joint demand equal to the fleet limit. Arms: ``per_agent_rule`` (admit iff the request is
within the quota) and ``cumulative_rule`` (the same check plus an atomic running total against the fleet limit).
Every decision lands in an AuditLog whose chain is verified. Simulated data only; wall-clock only in ``provenance``.
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
FLEET_LIMIT = 100 * UNIT
SIZES = (2, 8, 32, 128)
ARMS = ("per_agent_rule", "cumulative_rule")


def admit(arm: str, requests: list[int], log: AuditLog, kind: str, n: int) -> list[int]:
    """Process requests in order; return the admitted amounts."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    total = 0
    admitted: list[int] = []
    for agent, units in enumerate(requests):
        ok = units <= QUOTA
        code = "ALLOW" if ok else "DENY_AGENT_QUOTA"
        if ok and arm == "cumulative_rule" and total + units > FLEET_LIMIT:
            ok, code = False, "DENY_FLEET_LIMIT"
        log.append("fleet_overdraw_verdict", arm=arm, seq_kind=kind, n=n, agent=agent, code=code)
        if ok:
            total += units
            admitted.append(units)
    return admitted


def simulate(seed: int, rounds: int = 50) -> dict:
    rng = random.Random(seed)
    ratio: dict[str, dict[str, float]] = {a: {} for a in ARMS}
    benign_block: dict[str, float] = dict.fromkeys(ARMS, 0.0)
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    for arm in ARMS:
        log = AuditLog()
        decisions = 0
        blocked = 0
        total_benign = 0
        for n in SIZES:
            ratios = []
            for _ in range(rounds):
                got = admit(arm, [QUOTA] * n, log, "colluding", n)
                ratios.append(sum(got) / FLEET_LIMIT)
                decisions += n
            ratio[arm][str(n)] = sum(ratios) / rounds
            for _ in range(rounds):
                share = min(QUOTA, FLEET_LIMIT // n)
                req = [share - rng.randint(0, 1) for _ in range(n)]  # joint demand never above the limit
                got = admit(arm, req, log, "benign", n)
                blocked += len(got) < n
                total_benign += 1
                decisions += n
        benign_block[arm] = blocked / total_benign
        verified[arm] = bool(log.verify_full().ok)
        entries_ok[arm] = sum(e["kind"] == "fleet_overdraw_verdict" for e in log.entries) == decisions
    return {
        "config": {"rounds": rounds, "sizes": list(SIZES), "per_agent_quota_units": QUOTA // UNIT,
                   "fleet_limit_units": FLEET_LIMIT // UNIT},
        "fleet_overdraw": {
            "per_agent_rule_overdraw_ratio_n32": ratio["per_agent_rule"]["32"],
            "cumulative_rule_overdraw_ratio_n32": ratio["cumulative_rule"]["32"],
            "overdraw_ratio_by_n": ratio,
            "benign_false_block_rate": benign_block,
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate fleet-overdraw")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate fleet-overdraw " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
