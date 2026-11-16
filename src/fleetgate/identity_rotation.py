"""Seeded identity-rotation run: a colluder denied under a per-agent rule re-presents under a fresh identity.

Arms: ``per_agent_rule`` (each identity may be admitted ``PER_AGENT_BUDGET`` times per rack) and
``cumulative_rule`` (an atomic per-rack budget of ``CUMULATIVE_BUDGET`` across all identities). The rotating
colluder makes ``ATTEMPTS`` reversible restarts on one rack and, after a denial, retries under a fresh identity;
the static colluder keeps one identity. The benign row is ``CUMULATIVE_BUDGET`` restarts on one rack by distinct
identities. Every decision lands in an AuditLog whose chain is verified. Simulated data only; wall-clock only in
``provenance``.
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

PER_AGENT_BUDGET = 3
CUMULATIVE_BUDGET = 4
ATTEMPTS = 16
ARMS = ("per_agent_rule", "cumulative_rule")


class Gate:
    def __init__(self, arm: str, log: AuditLog, scenario: str):
        if arm not in ARMS:
            raise ValueError(f"unknown arm {arm!r}")
        self.arm, self.log, self.scenario = arm, log, scenario
        self.by_agent: dict[str, int] = {}
        self.total = 0
        self.decisions = 0

    def propose(self, agent: str, rack: str = "rack-0") -> bool:
        ok, code = True, "ALLOW"
        if self.arm == "per_agent_rule" and self.by_agent.get(agent, 0) >= PER_AGENT_BUDGET:
            ok, code = False, "DENY_AGENT_BUDGET"
        elif self.arm == "cumulative_rule" and self.total >= CUMULATIVE_BUDGET:
            ok, code = False, "DENY_RACK_CUMULATIVE"
        self.log.append("identity_rotation_verdict", arm=self.arm, scenario=self.scenario,
                        agent=agent, rack=rack, code=code)
        self.decisions += 1
        if ok:
            self.by_agent[agent] = self.by_agent.get(agent, 0) + 1
            self.total += 1
        return ok


def run_colluder(arm: str, log: AuditLog, rotate: bool, rng: random.Random) -> tuple[int, Gate]:
    """Make ATTEMPTS restarts; a denied attempt is retried once under a fresh identity when rotating."""
    gate = Gate(arm, log, "rotating" if rotate else "static")
    agent = f"agent-{rng.randrange(10**6):06d}-0"
    admitted = 0
    for i in range(ATTEMPTS):
        ok = gate.propose(agent)
        if not ok and rotate:
            agent = f"agent-{rng.randrange(10**6):06d}-{i + 1}"
            ok = gate.propose(agent)
        admitted += ok
    return admitted, gate


def run_benign(arm: str, log: AuditLog) -> tuple[int, Gate]:
    gate = Gate(arm, log, "benign")
    blocked = sum(not gate.propose(f"honest-{i}") for i in range(CUMULATIVE_BUDGET))
    return blocked, gate


def simulate(seed: int, rounds: int = 20) -> dict:
    rng = random.Random(seed)
    res: dict[str, dict[str, list[int]]] = {a: {"rotating": [], "static": [], "benign_blocked": []} for a in ARMS}
    verified: dict[str, bool] = {}
    entries_ok: dict[str, bool] = {}
    for arm in ARMS:
        log = AuditLog()
        decisions = 0
        for _ in range(rounds):
            for rotate, key in ((True, "rotating"), (False, "static")):
                n, g = run_colluder(arm, log, rotate, rng)
                res[arm][key].append(n)
                decisions += g.decisions
            b, g = run_benign(arm, log)
            res[arm]["benign_blocked"].append(b)
            decisions += g.decisions
        verified[arm] = bool(log.verify_full().ok)
        entries_ok[arm] = sum(e["kind"] == "identity_rotation_verdict" for e in log.entries) == decisions

    def mean(xs: list[int]) -> float:
        return sum(xs) / len(xs)

    pa, cu = res["per_agent_rule"], res["cumulative_rule"]
    return {
        "config": {"rounds": rounds, "attempts": ATTEMPTS, "per_agent_budget": PER_AGENT_BUDGET,
                   "cumulative_budget": CUMULATIVE_BUDGET},
        "identity_rotation": {
            "rotating_colluder_admit_count_cumulative_rule": mean(cu["rotating"]),
            "rotating_colluder_admit_count_per_agent_rule": mean(pa["rotating"]),
            "static_colluder_admit_count_per_agent_rule": mean(pa["static"]),
            "static_colluder_admit_count_cumulative_rule": mean(cu["static"]),
            "benign_false_blocks_cumulative_rule": mean(cu["benign_blocked"]),
            "benign_false_blocks_per_agent_rule": mean(pa["benign_blocked"]),
        },
        "entries_equal_decisions": entries_ok,
        "verify_full_ok": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate identity-rotation")
    ap.add_argument("--seeds", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seeds, args.rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seeds],
        "command": "python3 -m fleetgate identity-rotation " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0
