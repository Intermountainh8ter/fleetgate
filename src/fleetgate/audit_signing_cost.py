"""HMAC signing operations per decision for the audit log at fleet sizes 10, 100 and 1000.

Counts ``hmac.new`` calls during append and ``hmac.compare_digest`` calls during keyed ``verify_full``, and the
``unchecked_signatures`` of a keyless ``verify_full`` on the same log. Operations are counted, not timed; wall time
appears only in provenance. Simulated data only.
"""
from __future__ import annotations

import argparse
import hmac
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

FLEET_SIZES = (10, 100, 1000)
DECISIONS_PER_AGENT = 20
KEY = b"simulated-signing-cost-key"


class _CountingHmac:
    def __init__(self) -> None:
        self.new_calls = 0
        self.compare_calls = 0

    def new(self, *a, **k):
        self.new_calls += 1
        return hmac.new(*a, **k)

    def compare_digest(self, *a, **k):
        self.compare_calls += 1
        return hmac.compare_digest(*a, **k)


def _counted(fn):
    counter = _CountingHmac()
    real = audit.hmac
    audit.hmac = counter  # type: ignore[assignment]
    try:
        out = fn()
    finally:
        audit.hmac = real  # type: ignore[assignment]
    return out, counter


def run_fleet(seed: int, agents: int, per_agent: int = DECISIONS_PER_AGENT) -> dict[str, Any]:
    rng = random.Random(seed + agents)
    decisions = agents * per_agent
    stream = [(rng.randrange(agents), rng.choice(["ALLOW", "DENY", "NEEDS_APPROVAL"])) for _ in range(decisions)]

    def build():
        log = AuditLog(key=KEY, checkpoint_every=32)
        for agent, verdict in stream:
            log.append("gate_verdict", agent=agent, verdict=verdict)
        return log
    log, appended = _counted(build)
    entries = len(log.entries)
    keyed, kcount = _counted(log.verify_full)
    keyless_log = AuditLog(key=None, checkpoint_every=0)
    keyless_log.entries = log.entries
    keyless_log.key = None
    keyless = keyless_log.verify_full()
    return {"decisions": decisions, "entries": entries,
            "append_hmac_ops": appended.new_calls,
            "signing_ops_per_decision": appended.new_calls / decisions,
            "keyed_verify_ok": keyed.ok,
            "keyed_verify_signature_compares": kcount.compare_calls,
            "keyed_verify_hmac_recomputes": kcount.new_calls,
            "keyless_verify_ok": keyless.ok,
            "keyless_unchecked_signatures": keyless.unchecked_signatures}


def simulate(seed: int, sizes: tuple[int, ...] = FLEET_SIZES, per_agent: int = DECISIONS_PER_AGENT) -> dict:
    cells = {str(n): run_fleet(seed, n, per_agent) for n in sizes}
    return {"cells": cells,
            "signing_ops_per_decision_by_fleet_size": {k: v["signing_ops_per_decision"] for k, v in cells.items()}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fleetgate.audit_signing_cost")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = time.time()
    out = simulate(args.seed)
    out["provenance"] = {
        "started_at": started, "seeds": [args.seed],
        "command": "python3 -m fleetgate.audit_signing_cost " + " ".join(argv if argv is not None else sys.argv[1:]),
        "hardware": f"{platform.machine()} cpu, python {platform.python_version()}",
        "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "simulated: seeded in-process fleetgate decision stream",
                          "license": "MIT (own code)"}],
    }
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
