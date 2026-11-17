"""Suffix verification of an audit log from an externally anchored checkpoint, versus ``verify_full``.

Counts SHA-256 operations for both verifiers on logs of 1,000 / 10,000 / 100,000 entries with a fixed-length tail
written after the anchored checkpoint, and measures detection of seeded single-entry tampers on either side of it.
Simulated data only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import audit
from .audit import AuditLog

SCALES = (1_000, 10_000, 100_000)
TAIL = 20
TAMPERS = 200


class _CountingHashlib:
    def __init__(self) -> None:
        self.calls = 0

    def sha256(self, *a, **k):
        self.calls += 1
        return hashlib.sha256(*a, **k)


def suffix_verify(entries: list[dict], anchor_seq: int, anchor_hash: str) -> bool:
    """Check the chain only from the anchored checkpoint forward; entries before it are trusted via the anchor."""
    if anchor_seq >= len(entries) or entries[anchor_seq].get("hash") != anchor_hash:
        return False
    prev = anchor_hash
    for i in range(anchor_seq + 1, len(entries)):
        e = entries[i]
        body = {k: v for k, v in e.items() if k not in audit._SKIP}
        if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != AuditLog._digest(prev, body):
            return False
        prev = e["hash"]
    return True


def _build(n: int, seed: int) -> tuple[AuditLog, int, str]:
    rng = random.Random(seed * 1_000_003 + n)
    log = AuditLog(checkpoint_every=32)

    def add() -> None:
        log.append("collusion_verdict", agent=rng.randrange(8), round=rng.randrange(6), units=rng.randint(1, 10),
                   verdict=rng.choice(["ALLOW", "DENY"]), spent=rng.randint(0, 100))

    while len(log.entries) < n:
        add()
    cp = log.checkpoint()
    for _ in range(TAIL):
        add()
    return log, cp["seq"], cp["hash"]


def _measure(n: int, seed: int) -> dict:
    log, aseq, ahash = _build(n, seed)
    rng = random.Random(seed * 7_919 + n)
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        full_ok = log.verify_full().ok
        full_ops = counter.calls
        counter.calls = 0
        suffix_ok = suffix_verify(log.entries, aseq, ahash)
        suffix_ops = counter.calls
        det = {"before": {"suffix": 0, "full": 0}, "after": {"suffix": 0, "full": 0}}
        places = {"before": range(0, aseq), "after": range(aseq + 1, len(log.entries))}
        for name, rg in places.items():
            for _ in range(TAMPERS):
                i = rng.choice(list(rg)) if len(rg) < 1000 else rng.randrange(rg.start, rg.stop)
                if log.entries[i]["kind"] == "checkpoint":
                    i = i - 1 if i - 1 >= rg.start else i + 1
                old = log.entries[i].get("units")
                log.entries[i]["units"] = (old or 0) + 1
                det[name]["suffix"] += not suffix_verify(log.entries, aseq, ahash)
                det[name]["full"] += not log.verify_full().ok
                log.entries[i]["units"] = old
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    return {"entries": len(log.entries), "anchor_seq": aseq, "tail_entries": len(log.entries) - aseq - 1,
            "full_ok": full_ok, "suffix_ok": suffix_ok, "verify_full_hash_ops": full_ops,
            "suffix_hash_ops": suffix_ops, "tampers_per_placement": TAMPERS,
            "detect_rate": {k: {m: c / TAMPERS for m, c in v.items()} for k, v in det.items()}}


def simulate(seed: int, scales: tuple[int, ...] = SCALES) -> dict:
    per = {str(n): _measure(n, seed) for n in scales}
    lo, hi = per[str(scales[0])], per[str(scales[-1])]
    return {"scales": per,
            "hash_ops_ratio_100k_over_1k": hi["suffix_hash_ops"] / lo["suffix_hash_ops"],
            "verify_full_ops_ratio_100k_over_1k": hi["verify_full_hash_ops"] / lo["verify_full_hash_ops"],
            "all_untampered_ok": all(v["full_ok"] and v["suffix_ok"] for v in per.values())}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.audit_suffix")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = {"suffix_verify": simulate(args.seed)}
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.audit_suffix "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/pdf/2609.00275", "license": "none used; simulated data only"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
