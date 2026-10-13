from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .agents import HeuristicPlanner, Planner, Proposal, TriageAgent
from .audit import AuditLog
from .detect import Detector, Incident
from .fleet import Fleet
from .policy import Decision, Policy
from .runbooks import CATALOG

Approver = Callable[[Proposal, str], bool]


def deny_all(_: Proposal, __: str) -> bool:
    return False


def approve_all(_: Proposal, __: str) -> bool:
    return True


@dataclass
class IncidentRecord:
    incident: Incident
    status: str = "open"  # open | resolved | contained
    closed_tick: int | None = None
    executed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(self, fleet: Fleet, planner: Planner | None = None, policy: Policy | None = None,
                 approver: Approver = deny_all, audit: AuditLog | None = None,
                 triage: TriageAgent | None = None, detector: Detector | None = None):
        self.fleet = fleet
        self.planner = planner or HeuristicPlanner()
        self.policy = policy or Policy(fleet)
        self.approver, self.audit = approver, audit or AuditLog()
        self.triage = triage or TriageAgent(fleet)
        self.detector = detector or Detector()
        self.records: dict[str, IncidentRecord] = {}
        self.executed: list[tuple[int, str, str]] = []  # (tick, runbook, host) actually run

    def tick(self) -> list[IncidentRecord]:
        data = self.fleet.step()
        new = self.detector.observe(self.fleet.tick, data)
        for inc in new:
            rec = IncidentRecord(inc)
            self.records[inc.id] = rec
            self.audit.append("incident", tick=self.fleet.tick, id=inc.id, host=inc.host, signal=inc.signal)
            self._handle(rec)
        self._update_status()
        return [self.records[i.id] for i in new]

    def _handle(self, rec: IncidentRecord) -> None:
        inc = rec.incident
        tri = self.triage.triage(inc)
        self.audit.append("triage", id=inc.id, severity=tri.severity, summary=tri.summary)
        for p in self.planner.plan(inc, tri):
            v = self.policy.evaluate(p.runbook, p.host)
            self.audit.append("policy", id=inc.id, runbook=p.runbook, host=p.host,
                              decision=v.decision.value, reason=v.reason, rationale=p.rationale)
            if v.decision == Decision.DENY:
                rec.denied.append(f"{p.runbook}@{p.host}")
                continue
            if v.decision == Decision.NEEDS_APPROVAL:
                ok = self.approver(p, v.reason)
                self.audit.append("approval", id=inc.id, runbook=p.runbook, host=p.host, approved=ok)
                if not ok:
                    rec.denied.append(f"{p.runbook}@{p.host}")
                    continue
            CATALOG[p.runbook].apply(self.fleet, p.host)
            self.policy.record(p.runbook, p.host)
            self.executed.append((self.fleet.tick, p.runbook, p.host))
            rec.executed.append(f"{p.runbook}@{p.host}")
            self.audit.append("executed", id=inc.id, runbook=p.runbook, host=p.host, tick=self.fleet.tick)

    def _update_status(self) -> None:
        for rec in self.records.values():
            if rec.status != "open":
                continue
            h = self.fleet.hosts[rec.incident.host]
            if rec.incident.signal not in h.faults:
                rec.status, rec.closed_tick = "resolved", self.fleet.tick
            elif h.drained:
                rec.status, rec.closed_tick = "contained", self.fleet.tick
