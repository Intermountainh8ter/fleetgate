"""Seeded degenerate-caller rounds against the real Policy.evaluate/record.

Callers send ``PROPOSALS`` proposals, one per tick, to a fresh default Policy: ``honest`` (distinct reversible
runbooks on distinct hosts), ``empty`` (empty runbook and host ids), ``constant`` (one valid proposal repeated on
one host, each admitted one recorded as executed) and ``replay`` (every honest proposal re-sent on the next tick,
after the original was recorded; only the re-sends are counted). Every verdict lands in an AuditLog whose chain is
verified. Simulated data only; no wall-clock field outside ``provenance``.
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
from .policy import Decision, Policy, PolicyConfig
from .split_caller import _fleet, admissible_runbooks

PROPOSALS = 40
CALLERS = ("honest", "empty", "constant", "replay")


def _send(policy: Policy, fleet, log: AuditLog, caller: str, rnd: int, rid: str, hid: str, record: bool = True) -> bool:
    fleet.tick += 1
    try:
        v = policy.evaluate(rid, hid)
        ok, code = v.decision == Decision.ALLOW, v.code.value
    except Exception:  # the gate fails closed
        ok, code = False, "EXCEPTION_DENY"
    log.append("degenerate_verdict", caller=caller, round=rnd, code=code, allowed=ok)
    if ok and record:
        policy.record(rid, hid)
    return ok


def run_caller(caller: str, rid_pool: list[str], hosts: list[str], rnd: int, log: AuditLog, rng: random.Random):
    """Return (admitted, counted decisions, logged decisions)."""
    if caller not in CALLERS:
        raise ValueError(f"unknown caller {caller!r}")
    fleet = _fleet()
    policy = Policy(fleet, PolicyConfig())
    n = PROPOSALS
    admitted = counted = logged = 0
    if caller == "empty":
        for _ in range(n):
            admitted += _send(policy, fleet, log, caller, rnd, "", "")
            counted += 1
            logged += 1
    elif caller == "constant":
        rid, hid = rng.choice(rid_pool), hosts[0]
        for _ in range(n):
            admitted += _send(policy, fleet, log, caller, rnd, rid, hid)
            counted += 1
            logged += 1
    else:
        rids = [rng.choice(rid_pool) for _ in range(n)]
        picks = rng.sample(hosts, min(n, len(hosts)))
        for i in range(n):
            rid, hid = rids[i], picks[i % len(picks)]
            ok = _send(policy, fleet, log, caller, rnd, rid, hid)
            logged += 1
            if caller == "honest":
                admitted += ok
                counted += 1
            else:
                admitted += _send(policy, fleet, log, caller, rnd, rid, hid)
                counted += 1
                logged += 1
    return admitted, counted, logged


def simulate(seed: int, rounds: int = 100) -> dict:
    rng = random.Random(seed)
    pool = admissible_runbooks()
    if not pool:
        raise RuntimeError("no admissible reversible runbooks")
    hosts = list(_fleet().hosts)
    plan = []
    for _ in range(rounds):
        h = hosts[:]
        rng.shuffle(h)
        plan.append((h, rng.getrandbits(32)))
    rates: dict[str, float] = {}
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    codes: dict[str, dict[str, int]] = {}
    for caller in CALLERS:
        log = AuditLog()
        adm = cnt = logged = 0
        for i, (h, s) in enumerate(plan):
            a, c, lg = run_caller(caller, pool, h, i, log, random.Random(s))
            adm, cnt, logged = adm + a, cnt + c, logged + lg
        rates[caller] = adm / cnt
        verified[caller] = bool(log.verify_full().ok)
        dec = [e for e in log.entries if e["kind"] == "degenerate_verdict"]
        entries_ok[caller] = len(dec) == logged
        tally: dict[str, int] = {}
        for e in dec:
            tally[e["code"]] = tally.get(e["code"], 0) + 1
        codes[caller] = dict(sorted(tally.items()))
    return {
        "config": {"rounds": rounds, "proposals_per_caller": PROPOSALS, "policy": "default",
                   "cooldown_ticks": PolicyConfig().cooldown_ticks, "runbook_pool": len(pool)},
        "degenerate": {
            "honest_caller_admit_rate": rates["honest"],
            "empty_caller_admit_rate": rates["empty"],
            "constant_caller_admit_rate": rates["constant"],
            "replay_caller_admit_rate": rates["replay"],
            "verdict_codes_by_caller": codes,
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate degenerate-caller")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=100)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate degenerate-caller " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
