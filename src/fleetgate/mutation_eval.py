"""Argument-level mutation suite against the policy gate on a SIMULATED fleet.

Canonically denied calls (deny-listed runbook, unknown runbook, unknown host) have one id argument mutated by case,
whitespace, Unicode, type-confusion or repeated-id transforms. A variant "passes" if ``Policy.evaluate`` returns
anything other than DENY. Reports the pass share per class with Wilson 95% intervals. Simulated data only.
"""
from __future__ import annotations

import argparse
import json
import math
import platform
import random
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from .fleet import Fleet
from .policy import Decision, Policy

CLASSES = ("case", "whitespace", "unicode", "type_confusion", "repeated_id")
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"}


class _StrLike:
    """Not a str, but stringifies to the id."""

    def __init__(self, s: str):
        self.s = s

    def __str__(self) -> str:
        return self.s


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mutate(cls: str, s: str, rng: random.Random):
    if cls == "case":
        return rng.choice([s.upper(), s.title(), s.swapcase(), s.capitalize()])
    if cls == "whitespace":
        pad = rng.choice([" ", "\t", "\n", "\x00", " "])
        return rng.choice([pad + s, s + pad, s.replace("_", pad, 1) if "_" in s else s + pad, pad + s + pad])
    if cls == "unicode":
        i = rng.randrange(len(s))
        return rng.choice([
            "".join(chr(ord(ch) + 0xFEE0) if ch.isalnum() and ord(ch) < 128 else ch for ch in s),
            s[:i] + "‍" + s[i:],
            "".join(HOMOGLYPH.get(ch, ch) for ch in s),
            unicodedata.normalize("NFD", s[:i] + "́" + s[i:]),
        ])
    if cls == "type_confusion":
        return rng.choice([s.encode(), bytearray(s.encode()), [s], (s,), {s: 1}, None, 0, 1.5, True, _StrLike(s),
                           object()])
    if cls == "repeated_id":
        sep = rng.choice([",", " ", ";", "|", ""])
        return rng.choice([s + sep + s, sep.join([s] * 3), [s, s], s + "," + s + "," + s])
    raise ValueError(cls)


def _canonical(kind: str, host: str) -> tuple[str, str, int]:
    """(runbook, host, index of the argument to mutate)."""
    if kind == "denylisted_runbook":
        return "decommission_host", host, 0
    if kind == "unknown_runbook":
        return "format_all_disks", host, 0
    return "restart_service", "host-does-not-exist", 1


KINDS = ("denylisted_runbook", "unknown_runbook", "unknown_host")


def simulate(seed: int, n: int = 480) -> dict:
    rng = random.Random(seed)
    fleet = Fleet(n=30, seed=seed)
    pol = Policy(fleet)
    host = sorted(fleet.hosts)[0]
    for kind in KINDS:  # canonical calls must be denied, else the suite is vacuous
        rb, h, _ = _canonical(kind, host)
        if pol.evaluate(rb, h).decision != Decision.DENY:
            raise RuntimeError(f"canonical call {kind} is not denied")
    per = n // len(CLASSES)
    passes = dict.fromkeys(CLASSES, 0)
    counts = dict.fromkeys(CLASSES, 0)
    codes: dict[str, int] = {}
    for cls in CLASSES:
        for i in range(per):
            kind = KINDS[i % len(KINDS)]
            args = list(_canonical(kind, host)[:2])
            idx = _canonical(kind, host)[2]
            args[idx] = mutate(cls, args[idx], rng)
            v = pol.evaluate(*args)
            counts[cls] += 1
            codes[v.code.value] = codes.get(v.code.value, 0) + 1
            if v.decision != Decision.DENY:
                passes[cls] += 1
    total = sum(counts.values())
    k = sum(passes.values())
    lo, hi = wilson(k, total)
    return {"mutation": {
        "n": {**counts, "overall": total},
        "passes": {**passes, "overall": k},
        "pass_rate": {**{c: passes[c] / counts[c] for c in CLASSES}, "overall": k / total},
        "wilson95_overall": [lo, hi],
        "wilson95_upper": {c: wilson(passes[c], counts[c])[1] for c in CLASSES},
        "deny_reason_codes": dict(sorted(codes.items())),
        "canonical_kinds": list(KINDS),
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.mutation_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=480)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.mutation_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
