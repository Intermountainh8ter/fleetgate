"""Gate-bypass detection: hash chain, gate-side counter and executor-side reconciliation (SIMULATED).

A fraction of executions skips ``Policy.evaluate`` and leaves no audit entry. Chain-only arm: ``verify_full``.
Gate-counter arm: the gate's issued-decision count versus logged ``gate_verdict`` entries. Reconciliation arm: the
executor's own execution count versus logged ALLOW verdicts. Simulated data only.
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
from .fleet import Fleet
from .policy import Decision, Policy
from .runbooks import CATALOG, Tier


def _round(rng: random.Random, fleet: Fleet, rbs: list[str], hosts: list[str],
           n_proposals: int, bypass_p: float) -> tuple[bool, bool, bool, bool]:
    """Return (any_bypass, chain_flag, gate_counter_flag, reconcile_flag)."""
    pol, log = Policy(fleet), AuditLog(checkpoint_every=8)
    executed = bypassed = 0
    for _ in range(n_proposals):
        rb, host = rng.choice(rbs), rng.choice(hosts)
        if rng.random() < bypass_p:
            executed += 1
            bypassed += 1
            continue
        v = pol.evaluate(rb, host)
        log.append("gate_verdict", runbook=rb, host=host, verdict=v.decision.value)
        if v.decision == Decision.ALLOW:
            executed += 1
            log.append("execution", runbook=rb, host=host)
    allows = sum(1 for e in log.of_kind("gate_verdict") if e["verdict"] == Decision.ALLOW.value)
    chain = not log.verify_full().ok
    gate = chain or sum(pol.decisions.values()) != len(log.of_kind("gate_verdict"))
    reconcile = chain or executed != allows
    return bypassed > 0, chain, gate, reconcile


def simulate(seed: int, n_rounds: int = 1000, n_proposals: int = 20, bypass_p: float = 0.2) -> dict:
    rng = random.Random(seed)
    fleet = Fleet(n=30, seed=seed)
    probe = Policy(fleet)
    rbs = sorted(r for r, rb in CATALOG.items() if rb.tier == Tier.REVERSIBLE
                 and r not in probe.cfg.deny_list)
    hosts = sorted(fleet.hosts)
    with_b = [0, 0, 0, 0]  # rounds, chain, gate, reconcile
    without = [0, 0, 0, 0]
    for _ in range(n_rounds):
        any_b, c, g, r = _round(rng, Fleet(n=30, seed=rng.randrange(2**31)), rbs, hosts, n_proposals, bypass_p)
        t = with_b if any_b else without
        t[0] += 1
        t[1] += c
        t[2] += g
        t[3] += r
    share = lambda t, i: t[i] / t[0] if t[0] else 0.0  # noqa: E731
    return {"bypass": {
        "n_rounds": n_rounds, "proposals_per_round": n_proposals, "bypass_fraction": bypass_p,
        "rounds_with_bypass": with_b[0], "rounds_without_bypass": without[0],
        "detected_share_chain_only": share(with_b, 1),
        "detected_share_gate_counter": share(with_b, 2),
        "detected_share_reconcile": share(with_b, 3),
        "false_flag_rate_chain_only": share(without, 1),
        "false_flag_rate_gate_counter": share(without, 2),
        "false_flag_rate_reconcile": share(without, 3),
    }}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.bypass_reconcile_eval")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n-rounds", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed, args.n_rounds)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.bypass_reconcile_eval "
        + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
