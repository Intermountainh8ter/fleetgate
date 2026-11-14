"""Detection of omitted gate decisions: hash chain alone versus chain plus a gate-side decision counter.

Three omission types on seeded SIMULATED logs: tail truncation (last k entries dropped), middle deletion (k decision
entries removed from inside the log) and never-written decisions (the gate decided but the entries were not appended).
Chain-only arm: ``verify_full`` with no anchors. Counter arm: also compares the gate's issued-decision count with the
number of decision entries in the log. Simulated data only.
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

KINDS = ("tail_truncation", "middle_deletion", "never_written")
DECISION = "gate_verdict"
TAIL_PAD = 5  # decisions appended after the last checkpoint so a tail cut removes decisions only


def _decide(log: AuditLog, rng: random.Random, i: int) -> None:
    log.append(DECISION, n=i, agent=rng.randrange(8), action=rng.choice(["drain", "reboot", "restart"]),
               verdict=rng.choice(["ALLOW", "DENY", "NEEDS_APPROVAL"]))


def _build(rng: random.Random, never_written: int = 0) -> tuple[AuditLog, int]:
    """Return (log, decisions issued by the gate). ``never_written`` random decisions are decided but not appended."""
    log = AuditLog(checkpoint_every=8)
    total = rng.randint(30, 80)
    skip = set(rng.sample(range(total + TAIL_PAD), never_written))
    for i in range(total):
        if i in skip:
            continue
        _decide(log, rng, i)
    log.checkpoint_every = 0
    for i in range(total, total + TAIL_PAD):
        if i in skip:
            continue
        _decide(log, rng, i)
    return log, total + TAIL_PAD


def _decisions_in_log(log: AuditLog) -> int:
    return len(log.of_kind(DECISION))


def _trial(kind: str, rng: random.Random) -> tuple[bool, bool]:
    k = rng.randint(1, 5)
    if kind == "never_written":
        log, issued = _build(rng, k)
    else:
        log, issued = _build(rng)
        if kind == "tail_truncation":
            del log.entries[-k:]
        else:
            idx = [i for i, e in enumerate(log.entries) if e["kind"] == DECISION]
            for i in sorted(rng.sample(idx[:-TAIL_PAD], k), reverse=True):
                del log.entries[i]
    chain = not log.verify_full().ok
    counter = chain or _decisions_in_log(log) != issued
    return chain, counter


def simulate(seed: int, n: int = 1000) -> dict:
    chain_rate, counter_rate = {}, {}
    for kind in KINDS:
        rng = random.Random(f"{seed}:{kind}")
        c = k = 0
        for _ in range(n):
            a, b = _trial(kind, rng)
            c += a
            k += b
        chain_rate[f"{kind}_chain_only"] = c / n
        counter_rate[f"{kind}_with_counter"] = k / n
    return {"logs_per_type": n, "dropped_per_log": [1, 5],
            "detection_rate": {**chain_rate, **counter_rate}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.omission_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = {"omission": simulate(args.seed, args.n)}
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.omission_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
