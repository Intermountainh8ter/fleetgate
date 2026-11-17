"""Policy-profile hash in the audit log, and replay of a logged request stream under other profiles.

Each gate decision is logged with ``profile_hash`` (sha256 of the canonical policy config). The logged
(runbook, host) stream is replayed under the same, the strict and a mutated profile and decisions that flip are
counted. With the hash field stripped from a copy of the log, no decision can be attributed to a profile. Simulated
data only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog, canonical
from .fleet import Fleet
from .policy import Policy, PolicyConfig
from .runbooks import CATALOG


def profile_hash(cfg: PolicyConfig) -> str:
    return hashlib.sha256(canonical(cfg.to_dict()).encode()).hexdigest()


def mutated_profile() -> PolicyConfig:
    cfg = PolicyConfig.from_dict(PolicyConfig().to_dict())
    cfg.name = "mutated"
    cfg.protected_roles = set()
    cfg.deny_list = set()
    return cfg


def _fleet() -> Fleet:
    return Fleet(n=40, seed=0)


def log_stream(seed: int, proposals: int, cfg: PolicyConfig) -> AuditLog:
    rng = random.Random(seed)
    fleet = _fleet()
    policy = Policy(fleet, cfg)
    ids, hosts = sorted(CATALOG), sorted(fleet.hosts)
    h = profile_hash(cfg)
    log = AuditLog(checkpoint_every=0)
    for _ in range(proposals):
        rb, host = rng.choice(ids), rng.choice(hosts)
        log.append("gate_decision", runbook=rb, host=host, decision=policy.evaluate(rb, host).decision.value,
                   profile_hash=h)
    return log


def replay_decisions(log: AuditLog, cfg: PolicyConfig) -> list[str]:
    policy = Policy(_fleet(), cfg)
    return [policy.evaluate(e["runbook"], e["host"]).decision.value
            for e in log.entries if e["kind"] == "gate_decision"]


def flip_rate(log: AuditLog, cfg: PolicyConfig) -> float:
    logged = [e["decision"] for e in log.entries if e["kind"] == "gate_decision"]
    new = replay_decisions(log, cfg)
    return sum(a != b for a, b in zip(logged, new)) / len(logged)


def attributable(entries: list[dict], known: dict[str, str]) -> int:
    return sum(e["kind"] == "gate_decision" and e.get("profile_hash") in known for e in entries)


def simulate(seed: int, proposals: int) -> dict:
    default, strict, mutated = PolicyConfig(), PolicyConfig.load("strict"), mutated_profile()
    known = {profile_hash(c): c.name for c in (default, strict, mutated)}
    log = log_stream(seed, proposals, default)
    stripped = copy.deepcopy(log)
    for e in stripped.entries:
        e.pop("profile_hash", None)
    logged = [e["decision"] for e in log.entries]
    return {
        "proposals": proposals,
        "logged_decision_counts": {d: logged.count(d) for d in sorted(set(logged))},
        "profiles": {c.name: profile_hash(c)[:16] for c in (default, strict, mutated)},
        "replay": {
            "flip_rate_same_profile": flip_rate(log, default),
            "flip_rate_strict_vs_logged": flip_rate(log, strict),
            "flip_rate_mutated_vs_logged": flip_rate(log, mutated),
        },
        "attribution": {
            "attributable_with_hash": attributable(log.entries, known),
            "attributable_stripped": attributable(stripped.entries, known),
        },
        "chain": {
            "verifies_with_hash_field": log.verify_full().ok,
            "verifies_after_strip": stripped.verify_full().ok,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.policy_replay")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--proposals", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.proposals)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.policy_replay "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-repo fleet simulator", "license": "MIT (repo)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
