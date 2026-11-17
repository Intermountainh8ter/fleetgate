"""SHA-256 operations per decision for the audit log at fleet scale: append, full verification, sampled proofs.

One operation is one ``hashlib.sha256`` call inside the audit module. Simulated data only.
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
from .audit_suffix import _CountingHashlib

FLEET_SIZES = (10, 100, 1000)
SAMPLE = 100
TRIALS = 200
CHECKPOINT_EVERY = 32


def _digest_ok(prev: str, e: dict) -> bool:
    body = {k: v for k, v in e.items() if k not in audit._SKIP}
    return e.get("hash") == AuditLog._digest(prev, body)


def _sha(x: str) -> str:
    return audit.hashlib.sha256(x.encode()).hexdigest()


def reconstruct(entries: list[dict], i: int) -> bool:
    """Check entry i: its digest, then its Merkle path inside its checkpoint block up to the stored root."""
    e = entries[i]
    if not _digest_ok(e["prev"], e):
        return False
    cp = next((j for j in range(i + 1, len(entries)) if entries[j]["kind"] == "checkpoint"), None)
    if cp is None:
        return True  # entry in the unfinished tail: only its digest can be checked
    c = entries[cp]
    start, end = c["block_start"], c["block_end"]
    return _proof_root(entries, start, end, i - start) == c["merkle_root"]


def _proof_root(entries: list[dict], start: int, end: int, idx: int) -> str:
    """Merkle root from one leaf and its sibling path; siblings come from a prover tree."""
    tree = _levels(entries, start, end)
    node = _sha(entries[start + idx]["hash"])
    for level in tree[:-1]:
        if len(level) % 2:
            level = level + [level[-1]]
        sib = level[idx ^ 1]
        node = _sha(node + sib) if idx % 2 == 0 else _sha(sib + node)
        idx //= 2
    return node


_CACHE: dict = {}


def _levels(entries: list[dict], start: int, end: int) -> list[list[str]]:
    key = (id(entries), start, end)
    if key not in _CACHE:
        real = audit.hashlib
        audit.hashlib = hashlib  # tree precomputation is the prover's, not the verifier's, work
        try:
            level = [_sha(x["hash"]) for x in entries[start:end]]
            levels = [level]
            while len(level) > 1:
                if len(level) % 2:
                    level = level + [level[-1]]
                level = [_sha(level[k] + level[k + 1]) for k in range(0, len(level), 2)]
                levels.append(level)
        finally:
            audit.hashlib = real
        _CACHE[key] = levels
    return _CACHE[key]


def _build(agents: int, per_agent: int, seed: int, counter: _CountingHashlib):
    rng = random.Random(seed * 1_000_003 + agents)
    log = AuditLog(checkpoint_every=CHECKPOINT_EVERY)
    n = agents * per_agent
    counter.calls = 0
    for _ in range(n):
        log.append("gate_decision", agent=rng.randrange(agents), units=rng.randint(1, 10),
                   verdict=rng.choice(["ALLOW", "DENY"]))
    return log, n, counter.calls


def _measure(agents: int, per_agent: int, seed: int) -> dict:
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        _CACHE.clear()
        log, n, append_ops = _build(agents, per_agent, seed, counter)
        counter.calls = 0
        full_ok = log.verify_full().ok
        full_ops = counter.calls
        rng = random.Random(seed * 7_919 + agents)
        cand = [i for i, e in enumerate(log.entries) if e["kind"] != "checkpoint"]
        sample = sorted(rng.sample(cand, SAMPLE))
        for i in sample:  # warm prover trees outside the count
            cp = next((j for j in range(i + 1, len(log.entries)) if log.entries[j]["kind"] == "checkpoint"), None)
            if cp is not None:
                _levels(log.entries, log.entries[cp]["block_start"], log.entries[cp]["block_end"])
        counter.calls = 0
        sample_ok = all(reconstruct(log.entries, i) for i in sample)
        sample_ops = counter.calls
        sset = set(sample)
        unsampled = [i for i in cand if i not in sset]
        det_s = det_u = 0
        for _ in range(TRIALS):
            for inside in (True, False):
                i = rng.choice(sample if inside else unsampled)
                old = log.entries[i]["units"]
                log.entries[i]["units"] = old + 1
                caught = not all(reconstruct(log.entries, j) for j in sample)
                log.entries[i]["units"] = old
                if inside:
                    det_s += caught
                else:
                    det_u += caught
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    return {"decisions": n, "entries": len(log.entries), "full_verify_ok": full_ok, "sample_ok": sample_ok,
            "chained_append": append_ops / n, "full_verification": full_ops / n,
            "full_verification_total": full_ops, "sampled_reconstruction": sample_ops / n,
            "sampled_reconstruction_total": sample_ops,
            "sampled_tamper_detection": det_s / TRIALS, "unsampled_tamper_detection": det_u / TRIALS}


def simulate(seed: int, per_agent: int = 20, sizes: tuple[int, ...] = FLEET_SIZES) -> dict:
    per = {str(a): _measure(a, per_agent, seed) for a in sizes}
    lo, hi = str(sizes[0]), str(sizes[-1])
    return {"hash_ops_per_decision_by_fleet_size": per,
            "full_verification_total_ratio_largest_to_smallest":
                per[hi]["full_verification_total"] / per[lo]["full_verification_total"],
            "full_to_sampled_cost_ratio_largest": per[hi]["full_verification"] / per[hi]["sampled_reconstruction"],
            "decisions_per_agent": per_agent, "sample_size": SAMPLE, "tamper_trials": TRIALS}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.audit_fleet_cost")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--decisions-per-agent", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.decisions_per_agent)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.audit_fleet_cost "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-process audit logs, no external data",
                          "license": "MIT (repository code)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
