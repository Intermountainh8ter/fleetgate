"""Anchor-interval x tamper-class matrix for the audit log.

Each seeded SIMULATED log is built through ``AuditLog`` with ``checkpoint_every=interval`` and a ``MemoryAnchor``.
Six tamper classes are applied to a copy and ``verify_full`` is run twice: unanchored, and with the anchors captured
while the original log was written. A "rehashed" tamper rebuilds the log through ``AuditLog`` from the edited record
list, so every hash, checkpoint and Merkle root is internally consistent (an attacker with write access and no HMAC
key). The result is the share of tampers each verifier fails to flag. Simulated data only.
"""
from __future__ import annotations

import argparse
import copy
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog, MemoryAnchor

CLASSES = ("inplace_edit", "rehashed_edit", "rehashed_delete", "rehashed_reorder", "tail_truncation",
           "whole_log_replacement")
_SKIP = {"seq", "kind", "prev", "hash", "sig"}


def make_records(rng: random.Random, n: int) -> list[dict[str, Any]]:
    return [{"agent": rng.randrange(8), "units": rng.randint(1, 10), "verdict": rng.choice(["ALLOW", "DENY"])}
            for _ in range(n)]


def build(records: list[dict[str, Any]], interval: int) -> tuple[AuditLog, dict[int, str]]:
    anchor = MemoryAnchor()
    log = AuditLog(checkpoint_every=interval, anchor=anchor)
    for r in records:
        log.append("agent_record", **r)
    return log, dict(anchor.roots)


def _undetected(log: AuditLog, anchors: dict[int, str]) -> tuple[bool, bool]:
    return log.verify_full().ok, log.verify_full(anchors=anchors).ok


def tamper_once(cls: str, rng: random.Random, records: list[dict[str, Any]], interval: int,
                original: AuditLog) -> AuditLog:
    n = len(records)
    if cls == "inplace_edit":
        log = AuditLog(checkpoint_every=0)
        log.entries = copy.deepcopy(original.entries)
        idx = [i for i, e in enumerate(log.entries) if e["kind"] != "checkpoint"]
        log.entries[rng.choice(idx)]["units"] += 1000
        return log
    if cls == "rehashed_edit":
        recs = copy.deepcopy(records)
        recs[rng.randrange(n)]["units"] += 1000
        return build(recs, interval)[0]
    if cls == "rehashed_delete":
        recs = copy.deepcopy(records)
        del recs[rng.randrange(n)]
        return build(recs, interval)[0]
    if cls == "rehashed_reorder":
        recs = copy.deepcopy(records)
        i = rng.randrange(n - 1)
        recs[i], recs[i + 1] = recs[i + 1], recs[i]
        recs[i]["units"] += 1  # guarantee the swap changes content even if neighbours are equal
        return build(recs, interval)[0]
    if cls == "tail_truncation":
        log = AuditLog(checkpoint_every=0)
        total = len(original.entries)
        log.entries = copy.deepcopy(original.entries[:total - rng.randint(1, total // 2)])
        return log
    if cls == "whole_log_replacement":
        return build(make_records(rng, n), interval)[0]
    raise ValueError(cls)


def simulate(seed: int, logs: int, records: int, intervals: list[int]) -> dict:
    counts = {str(iv): {c: {"anchored": 0, "unanchored": 0} for c in CLASSES} for iv in intervals}
    for iv in intervals:
        for k in range(logs):
            rng = random.Random(f"{seed}:{iv}:{k}")
            recs = make_records(rng, records)
            original, anchors = build(recs, iv)
            for c in CLASSES:
                un_ok, an_ok = _undetected(tamper_once(c, rng, recs, iv, original), anchors)
                counts[str(iv)][c]["unanchored"] += un_ok
                counts[str(iv)][c]["anchored"] += an_ok
    rate = lambda mode: {iv: {c: counts[iv][c][mode] / logs for c in CLASSES} for iv in counts}  # noqa: E731
    return {"logs": logs, "records": records, "intervals": intervals,
            "undetected_rate_by_interval": rate("anchored"),
            "unanchored_undetected_rate_by_interval": rate("unanchored"),
            "undetected_counts": counts,
            "rehashed_edit_non_decreasing_in_interval": _non_decreasing(
                [counts[str(iv)]["rehashed_edit"]["anchored"] for iv in sorted(intervals)])}


def _non_decreasing(xs: list[float]) -> bool:
    return all(a <= b for a, b in zip(xs, xs[1:]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.anchor_matrix")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--logs", type=int, default=1000)
    ap.add_argument("--records", type=int, default=1000)
    ap.add_argument("--intervals", default="10,50,250")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.logs, args.records, [int(x) for x in args.intervals.split(",")])
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.anchor_matrix "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: fleetgate seeded audit record stream",
                          "license": "MIT (repo-internal synthetic data)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
