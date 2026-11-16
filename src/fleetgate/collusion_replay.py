"""Replay detector for the collusion simulation: rebuild cumulative admitted units from the audit log alone.

Each sequence of each arm of ``collusion`` gets its own AuditLog. ``replay_flag`` refuses a log that fails
``verify_full``, otherwise sums the units of ALLOW verdicts and flags the first entry where the total exceeds the
budget. Reported per arm: detection rate over budget-breaching sequences, false flags over non-breaching ones,
the lag in entries behind the first entry whose gate-recorded ``spent`` exceeded the budget, and the share of
breaching sequences the online gate itself denied at least once. A middle-deleted copy of every log is also
replayed and must be refused. Simulated data only.
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

from .audit import AuditLog
from .collusion import ARMS, FLEET_BUDGET, make_sequence, run_arm


def replay_flag(log: AuditLog, budget: int = FLEET_BUDGET) -> int | None:
    """Return the seq of the first entry whose cumulative ALLOWed units exceed ``budget``; None if never.

    Raises ValueError when the chain does not verify, so a tampered log is refused rather than replayed.
    """
    if not log.verify_full().ok:
        raise ValueError("audit chain failed verification; replay refused")
    total = 0
    for e in log.entries:
        if e["kind"] == "collusion_verdict" and e["verdict"] == "ALLOW":
            total += e["units"]
            if total > budget:
                return e["seq"]
    return None


def _truth_index(log: AuditLog, budget: int = FLEET_BUDGET) -> int | None:
    for e in log.entries:
        if e["kind"] == "collusion_verdict" and e["spent"] > budget:
            return e["seq"]
    return None


def _drop_middle_verdict(log: AuditLog) -> AuditLog:
    verdicts = [e["seq"] for e in log.entries if e["kind"] == "collusion_verdict"]
    victim = verdicts[len(verdicts) // 2]
    tampered = AuditLog(checkpoint_every=0)
    tampered.entries = [copy.deepcopy(e) for e in log.entries if e["seq"] != victim]
    return tampered


def simulate(seed: int, n_sequences: int = 1000) -> dict:
    rng = random.Random(seed)
    seqs = [make_sequence(rng) for _ in range(n_sequences)]
    rate, flagged, breached, false_flags, mean_lag = {}, {}, {}, {}, {}
    denied_online, tamper_rejected = {}, {}
    for arm in ARMS:
        n_breach = n_hit = n_false = n_online = n_rej = 0
        lags: list[int] = []
        for seq in seqs:
            log = AuditLog()
            spent = run_arm(arm, seq, log)
            flag = replay_flag(log)
            breach = spent > FLEET_BUDGET
            if breach:
                n_breach += 1
                n_hit += flag is not None
                n_online += any(e["verdict"] == "DENY" for e in log.of_kind("collusion_verdict"))
                truth = _truth_index(log)
                if flag is not None and truth is not None:
                    lags.append(flag - truth)
            else:
                n_false += flag is not None
            try:
                replay_flag(_drop_middle_verdict(log))
            except ValueError:
                n_rej += 1
        breached[arm], flagged[arm], false_flags[arm] = n_breach, n_hit, n_false
        rate[arm] = n_hit / n_breach if n_breach else None
        mean_lag[arm] = sum(lags) / len(lags) if lags else None
        denied_online[arm] = n_online
        tamper_rejected[arm] = n_rej / n_sequences
    return {
        "config": {"n_sequences": n_sequences, "fleet_budget": FLEET_BUDGET},
        "replay": {
            "detection_rate": rate,
            "breaching_sequences": breached,
            "flagged_breaches": flagged,
            "false_flags": false_flags,
            "mean_lag_entries": mean_lag,
            "breaches_denied_at_least_once_online": denied_online,
            "tampered_log_rejection_rate": tamper_rejected,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    res = simulate(args.seed, args.n)
    res["provenance"] = {
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "seeds": [args.seed],
        "command": "PYTHONPATH=src python3 -m fleetgate.collusion_replay "
                   + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.monotonic() - t0, 3),
        "data_sources": [{"url": "https://arxiv.org/pdf/2603.14332", "license": "none used; simulated data only"}],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
