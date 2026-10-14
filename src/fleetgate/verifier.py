"""VerifierAgent: after a runbook ran, re-read the host's metrics and check the runbook's probes.

If the probes fail and the runbook has a rollback partner, the verifier *proposes* the rollback;
like every other proposal it still has to pass the policy gate. Verification outcomes also feed
the gate's canary-first rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .agents import Proposal
from .fleet import Fleet
from .runbooks import CATALOG, Runbook


@dataclass
class Verification:
    runbook: str
    host: str
    tick: int
    ok: bool
    failed: list[str] = field(default_factory=list)
    rollback: Proposal | None = None
    hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"runbook": self.runbook, "host": self.host, "tick": self.tick, "ok": self.ok, "failed": self.failed,
                "rollback": self.rollback.to_dict() if self.rollback else None, "hosts": self.hosts}


class VerifierAgent:
    def __init__(self, fleet: Fleet, settle_ticks: int = 1):
        self.fleet = fleet
        self.settle = settle_ticks
        self.results: list[Verification] = []

    def due_at(self, rb: Runbook, executed_tick: int) -> int:
        return executed_tick + rb.duration_ticks + self.settle

    def verify(self, runbook_id: str, host_id: str, hosts: list[str] | None = None) -> Verification:
        rb = CATALOG[runbook_id]
        targets = hosts or [host_id]
        failed: list[str] = []
        for h in targets:
            if h not in self.fleet.hosts:
                failed.append(f"{h}: unknown host")
                continue
            for f in rb.verify_probes(self.fleet, h, self.fleet.last_sample.get(h)):
                failed.append(f"{h}: {f}")
        ok = not failed
        rollback = None
        if not ok and rb.rollback:
            rollback = Proposal(rb.rollback, host_id, f"rollback: {runbook_id} failed verification ({failed[0]})")
        v = Verification(runbook_id, host_id, self.fleet.tick, ok, failed, rollback, list(targets))
        self.results.append(v)
        return v
