"""Hash-chained vs plain audit append under an interleaved multi-agent stream, plus a stale-head writer.

Records from N agents are interleaved by a seeded schedule. Arms: ``chain_serialised`` (one writer appends through
``AuditLog``, checkpoints off, so the count is the append path alone), ``chain_serialised_checkpointed`` (default
checkpoint cadence), ``plain`` (JSONL lines, no hashing) and ``chain_stale_head`` (every collision, a second writer
builds its entry from the head it read before the previous append). Counts are deterministic; wall time appears only
in provenance. Simulated data only.
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
from typing import Any

from . import audit
from .audit import AuditLog

COLLISION_RATE = 0.01


class _CountingHashlib:
    def __init__(self) -> None:
        self.calls = 0

    def sha256(self, *a, **k):
        self.calls += 1
        return hashlib.sha256(*a, **k)


def make_stream(seed: int, agents: int, records: int) -> list[tuple[int, dict[str, Any]]]:
    rng = random.Random(seed)
    return [(rng.randrange(agents), {"round": i // agents, "units": rng.randint(1, 10),
                                     "verdict": rng.choice(["ALLOW", "DENY"])}) for i in range(records)]


def _size(entry: dict[str, Any]) -> int:
    return len(json.dumps(entry, sort_keys=True)) + 1


def _counted(fn):
    counter = _CountingHashlib()
    real = audit.hashlib
    audit.hashlib = counter  # type: ignore[assignment]
    try:
        out = fn()
    finally:
        audit.hashlib = real  # type: ignore[assignment]
    return out, counter.calls


def _chain_arm(stream, checkpoint_every: int) -> dict:
    def run():
        log = AuditLog(checkpoint_every=checkpoint_every)
        for agent, rec in stream:
            log.append("agent_record", agent=agent, **rec)
        return log
    log, ops = _counted(run)
    res = log.verify_full()
    total = sum(_size(e) for e in log.entries)
    return {"entries": len(log.entries), "append_hash_ops": ops, "verify_ok": res.ok,
            "first_bad_seq": res.first_bad_seq, "bytes_per_record": total / len(stream)}


def _plain_arm(stream) -> dict:
    def run():
        return [{"seq": i, "kind": "agent_record", "agent": a, **r} for i, (a, r) in enumerate(stream)]
    lines, ops = _counted(run)
    return {"entries": len(lines), "append_hash_ops": ops, "verify_ok": None, "first_bad_seq": None,
            "bytes_per_record": sum(_size(e) for e in lines) / len(stream)}


def _stale_arm(stream, seed: int) -> dict:
    rng = random.Random(seed + 1)
    log = AuditLog(checkpoint_every=0)
    collisions: list[int] = []
    for agent, rec in stream:
        if len(log.entries) >= 2 and rng.random() < COLLISION_RATE:
            # Second writer read the head before the previous append landed.
            stale = log.entries[-2]
            body = {"seq": stale["seq"] + 1, "kind": "agent_record", "agent": agent, **rec}
            h = AuditLog._digest(stale["hash"], body)
            collisions.append(len(log.entries))
            log.entries.append({**body, "prev": stale["hash"], "hash": h})
        else:
            log.append("agent_record", agent=agent, **rec)
    res = log.verify_full()
    return {"entries": len(log.entries), "collisions": len(collisions),
            "first_collision_index": collisions[0] if collisions else None,
            "verify_ok": res.ok, "first_bad_seq": res.first_bad_seq}


def simulate(seed: int, agents: int, records: int) -> dict:
    stream = make_stream(seed, agents, records)
    chain = _chain_arm(stream, 0)
    ckpt = _chain_arm(stream, 32)
    plain = _plain_arm(stream)
    stale = _stale_arm(stream, seed)
    per = {"chain_serialised": chain["append_hash_ops"] / records,
           "chain_serialised_checkpointed": ckpt["append_hash_ops"] / records,
           "plain": plain["append_hash_ops"] / records}
    return {"agents": agents, "records": records,
            "overhead": {"hash_ops_per_record_by_log": per,
                         "bytes_per_record_by_log": {"chain_serialised": chain["bytes_per_record"],
                                                     "plain": plain["bytes_per_record"]}},
            "arms": {"chain_serialised": chain, "chain_serialised_checkpointed": ckpt, "plain": plain,
                     "chain_stale_head": stale},
            "stale_head_detected": (not stale["verify_ok"]) and stale["collisions"] > 0}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.serialised_append")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--agents", type=int, default=8)
    ap.add_argument("--records", type=int, default=5000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.agents, args.records)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.serialised_append "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: fleetgate seeded multi-agent record stream",
                          "license": "MIT (repo-internal synthetic data)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
