"""Orchestrator: detect -> correlate -> triage -> root cause -> plan -> gate -> (approve) -> execute -> verify.

Every plan is pre-flighted through the policy gate as soon as it is produced (so the audit log shows
a verdict for every proposal, including the hundreds a jailbroken planner might emit); steps that
fail a structural check are pruned, the rest execute one per verification cycle: a step runs, the
VerifierAgent re-reads metrics after the runbook's duration, and only a verified step unlocks the
next one. Each step is re-evaluated by the gate at execution time, because fleet state changes
while a step waits. A failed verification proposes the rollback partner (through the gate) and
pages. NEEDS_APPROVAL steps wait in the approval queue; unanswered requests page after
`page_after_ticks` and expire after `expire_after_ticks`. Nothing here bypasses
`Policy.evaluate`, and in dry-run mode nothing mutates the fleet.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import islice
from typing import Any

from .agents import (
    AnyIncident,
    HeuristicPlanner,
    Planner,
    Proposal,
    RootCause,
    RootCauseAgent,
    Triage,
    TriageAgent,
    incident_hosts,
    incident_signal,
)
from .approvals import ApprovalQueue, ApprovalRequest, as_approver
from .audit import AuditLog
from .correlate import Correlator, GroupIncident
from .detect import BaseDetector, Incident, MultiDetector, ThresholdDetector
from .fleet import Fleet
from .policy import Decision, Policy, Reason, Verdict
from .runbooks import CATALOG
from .verifier import VerifierAgent

Approver = Callable[[Proposal, str], bool]

# Verdicts that cannot change by waiting: prune these steps at pre-flight.
STRUCTURAL_DENIALS = frozenset({Reason.UNKNOWN_RUNBOOK, Reason.UNKNOWN_HOST, Reason.DENY_LIST, Reason.FREEZE_WINDOW,
                                Reason.INTERNAL_ERROR})
# Verdicts that a later tick may clear: the step waits and is re-evaluated (bounded by MAX_STEP_WAIT).
TRANSIENT_DENIALS = frozenset({Reason.TICK_BUDGET, Reason.COOLDOWN, Reason.RATE_LIMIT, Reason.QUOTA_ROLE,
                               Reason.QUOTA_DC, Reason.CANARY_PENDING})
MAX_PLAN_STEPS = 16
MAX_STEP_WAIT = 20


MAX_PROPOSALS_READ = 10_000  # a planner is untrusted: never consume an unbounded plan
MAX_ID_LEN = 200


def sanitise_proposals(raw: Any) -> tuple[list[Proposal], int]:
    """Coerce untrusted planner output into well-typed Proposals. Returns (proposals, malformed_count).

    Anything that is not a Proposal with string runbook/host is dropped; ids are clamped so a megabyte-long
    "runbook name" cannot bloat the audit log (a clamped id can never equal a catalogue id, so it is still denied).
    """
    out: list[Proposal] = []
    malformed = 0
    for p in islice(raw, MAX_PROPOSALS_READ):
        if not (isinstance(p, Proposal) and isinstance(p.runbook, str) and isinstance(p.host, str)):
            malformed += 1
            continue
        rationale = p.rationale if isinstance(p.rationale, str) else ""
        out.append(Proposal(p.runbook[:MAX_ID_LEN], p.host[:MAX_ID_LEN], rationale[:300]))
    return out, malformed


def deny_all(_: Proposal, __: str) -> bool:
    return False


def approve_all(_: Proposal, __: str) -> bool:
    return True


@dataclass
class PlanStep:
    proposal: Proposal
    # pending | awaiting_approval | approved_waiting | verifying | verified | failed | denied | skipped | rolled_back
    status: str = "pending"
    verdict: Verdict | None = None
    request_id: str | None = None
    executed_tick: int | None = None
    verify_at: int | None = None
    hosts: list[str] = field(default_factory=list)
    is_rollback: bool = False
    waits: int = 0  # ticks spent on a transient denial

    def to_dict(self) -> dict[str, Any]:
        return {"runbook": self.proposal.runbook, "host": self.proposal.host, "status": self.status,
                "code": self.verdict.code.value if self.verdict else None, "request_id": self.request_id,
                "executed_tick": self.executed_tick, "is_rollback": self.is_rollback, "waits": self.waits}


@dataclass
class IncidentRecord:
    incident: AnyIncident
    status: str = "open"  # open | contained | resolved
    closed_tick: int | None = None
    contained_tick: int | None = None
    executed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    steps: list[PlanStep] = field(default_factory=list)
    triage: Triage | None = None
    root_cause: RootCause | None = None
    escalated: bool = False
    paged_tick: int | None = None
    verify_failures: int = 0
    rollbacks: list[str] = field(default_factory=list)
    plan_aborted: bool = False
    truncated: int = 0
    merged_into: str | None = None  # set when a later group incident absorbed this host incident

    @property
    def hosts(self) -> list[str]:
        return incident_hosts(self.incident)

    @property
    def signal(self) -> str:
        return incident_signal(self.incident)

    @property
    def is_group(self) -> bool:
        return isinstance(self.incident, GroupIncident)

    @property
    def active(self) -> bool:
        """True while the plan still has work to do (plans run to completion even after resolution)."""
        live = ("pending", "awaiting_approval", "approved_waiting", "verifying")
        return not self.plan_aborted and any(s.status in live for s in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.incident.id, "signal": self.signal, "hosts": self.hosts, "status": self.status,
                "opened_tick": self.incident.opened_tick, "closed_tick": self.closed_tick,
                "contained_tick": self.contained_tick,
                "severity": self.triage.severity if self.triage else None,
                "root_cause": self.root_cause.hypothesis if self.root_cause else None,
                "executed": self.executed, "denied": self.denied, "escalated": self.escalated,
                "paged_tick": self.paged_tick, "verify_failures": self.verify_failures, "rollbacks": self.rollbacks,
                "truncated": self.truncated, "merged_into": self.merged_into,
                "steps": [s.to_dict() for s in self.steps]}


class Orchestrator:
    def __init__(self, fleet: Fleet, planner: Planner | None = None, policy: Policy | None = None,
                 approver: Any = deny_all, audit: AuditLog | None = None, triage: TriageAgent | None = None,
                 detector: BaseDetector | MultiDetector | None = None, correlator: Correlator | None = None,
                 root_cause: RootCauseAgent | None = None, verifier: VerifierAgent | None = None,
                 dry_run: bool = False, correlate: bool = True, on_tick: Callable[[Orchestrator], None] | None = None,
                 max_plan_steps: int = MAX_PLAN_STEPS):
        self.fleet = fleet
        self.planner = planner or HeuristicPlanner()
        self.policy = policy or Policy(fleet)
        self.audit = audit or AuditLog()
        self.triage = triage or TriageAgent(fleet, protected=self.policy.cfg.protected_roles)
        self.detector = detector or ThresholdDetector()
        self.correlator = correlator or (Correlator(fleet.topology) if correlate else None)
        self.root_cause = root_cause or RootCauseAgent(fleet)
        self.verifier = verifier or VerifierAgent(fleet)
        self.dry_run = dry_run
        self.on_tick = on_tick
        self.max_plan_steps = max_plan_steps
        esc = self.policy.cfg.escalation
        self.approvals = ApprovalQueue(as_approver(approver), esc.get("page_after_ticks", 3),
                                       esc.get("expire_after_ticks", 12))
        self.records: dict[str, IncidentRecord] = {}
        self.executed: list[tuple[int, str, str]] = []  # (tick, runbook, host) actually run
        self.pages: list[dict[str, Any]] = []
        self.last_data: dict[str, dict[str, float]] = {}
        self._step_by_request: dict[str, tuple[IncidentRecord, PlanStep]] = {}
        self.tick_log: list[dict[str, Any]] = []
        self.audit.append("run_start", tick=fleet.tick, hosts=len(fleet.hosts), policy=self.policy.cfg.name,
                          dry_run=dry_run)

    # ---- main loop ---------------------------------------------------------------------------
    def tick(self) -> list[IncidentRecord]:
        data = self.fleet.step()
        self.last_data = data
        t = self.fleet.tick
        new = self.detector.observe(t, data)
        groups: list[GroupIncident] = []
        singles: list[Incident] = new
        if self.correlator is not None:
            groups, singles = self.correlator.correlate(t, new, set(data))
        opened: list[IncidentRecord] = []
        for g in groups:
            rec = IncidentRecord(g)
            self.records[g.id] = rec
            self.audit.append("group_incident", tick=t, id=g.id, scope=g.scope, scope_id=g.scope_id, signal=g.signal,
                              hypothesis=g.hypothesis, hosts=g.hosts, fraction=round(g.fraction, 3),
                              members=[m.id for m in g.members])
            for m in g.members:  # host incidents opened earlier fold into the group
                old = self.records.get(m.id)
                if old is not None and old.merged_into is None:
                    self._merge(old, rec)
            self._handle(rec)
            opened.append(rec)
        for inc in singles:
            rec = IncidentRecord(inc)
            self.records[inc.id] = rec
            self.audit.append("incident", tick=t, id=inc.id, host=inc.host, signal=inc.signal, detector=inc.detector,
                              score=round(inc.score, 2))
            self._handle(rec)
            opened.append(rec)
        self._poll_approvals()
        self._run_verifications()
        for rec in list(self.records.values()):
            if rec.active:
                self._advance_plan(rec)
        self._update_status()
        self.tick_log.append(self.snapshot())
        if self.on_tick:
            self.on_tick(self)
        return opened

    def run(self, ticks: int) -> None:
        for _ in range(ticks):
            self.tick()

    # ---- incident handling -------------------------------------------------------------------
    def _handle(self, rec: IncidentRecord) -> None:
        inc = rec.incident
        t = self.fleet.tick
        tri = self.triage.triage(inc)
        rec.triage = tri
        self.audit.append("triage", tick=t, id=inc.id, severity=tri.severity, summary=tri.summary,
                          blast_radius=tri.blast_radius.to_dict() if tri.blast_radius else None)
        open_signals = {h: self.detector.open_signals(h) for h in rec.hosts}
        rc = self.root_cause.analyse(inc, open_signals)
        rec.root_cause = rc
        self.audit.append("root_cause", tick=t, id=inc.id, hypothesis=rc.hypothesis, confidence=round(rc.confidence, 2),
                          scope=rc.scope, scope_id=rc.scope_id, contributing=rc.contributing, evidence=rc.evidence[:4])
        try:
            proposals, malformed = sanitise_proposals(self.planner.plan(inc, tri))
            if malformed:
                self.audit.append("plan_filtered", tick=t, id=inc.id,
                                  dropped=[f"{malformed} malformed proposal(s) (not str runbook/host)"])
        except Exception as exc:  # a crashing planner escalates; it never blocks the gate
            proposals = []
            self.audit.append("escalation", tick=t, id=inc.id, reason=f"planner error: {type(exc).__name__}")
        outcome = getattr(self.planner, "last", None)
        if outcome is not None and getattr(outcome, "escalated", False):
            self.audit.append("escalation", tick=t, id=inc.id, reason="invalid plan", errors=list(outcome.errors)[:5])
            self._page(rec, "planner produced no valid plan after retry")
        if outcome is not None and getattr(outcome, "dropped", None):
            self.audit.append("plan_filtered", tick=t, id=inc.id, dropped=list(outcome.dropped)[:20])
        if len(proposals) > self.max_plan_steps:
            rec.truncated = len(proposals) - self.max_plan_steps
            self.audit.append("plan_truncated", tick=t, id=inc.id, kept=self.max_plan_steps, dropped=rec.truncated)
            proposals = proposals[:self.max_plan_steps]
        if not proposals and not rec.escalated:
            self._page(rec, "no plan available")
        rec.steps = [PlanStep(p) for p in proposals]
        self.audit.append("plan", tick=t, id=inc.id, steps=[p.to_dict() for p in proposals], n_steps=len(proposals))
        self._preflight(rec)
        self._advance_plan(rec)

    def _preflight(self, rec: IncidentRecord) -> None:
        """Gate every step now; prune the ones no amount of waiting can fix."""
        for step in rec.steps:
            v = self.policy.evaluate(step.proposal.runbook, step.proposal.host)
            step.verdict = v
            pruned = v.decision == Decision.DENY and v.code in STRUCTURAL_DENIALS
            # A pre-flight verdict on a later step is provisional (earlier steps may satisfy its preconditions);
            # only a structural denial is final at this point.
            self._audit_policy(rec, step, v, phase="preflight", provisional=not pruned)
            if pruned:
                step.status = "denied"
                rec.denied.append(f"{step.proposal.runbook}@{step.proposal.host}")

    def _advance_plan(self, rec: IncidentRecord) -> None:
        """Execute pending steps in order until one needs to wait (approval, verification or a transient denial)."""
        if rec.plan_aborted:
            return
        for step in rec.steps:
            if step.status in ("awaiting_approval", "approved_waiting", "verifying"):
                return  # wait for it
            if step.status != "pending":
                continue
            v = self.policy.evaluate(step.proposal.runbook, step.proposal.host)
            step.verdict = v
            self._audit_policy(rec, step, v)
            if v.decision == Decision.DENY:
                if v.code in TRANSIENT_DENIALS and step.waits < MAX_STEP_WAIT:
                    step.waits += 1
                    return  # try again next tick
                self._deny_step(rec, step, v)
                return
            if v.decision == Decision.NEEDS_APPROVAL:
                assert v.requirement is not None
                req = self.approvals.submit(rec.incident.id, step.proposal.runbook, step.proposal.host,
                                            step.proposal.rationale, v.requirement, self.fleet.tick)
                step.request_id = req.id
                self._step_by_request[req.id] = (rec, step)
                self.audit.append("approval_request", tick=self.fleet.tick, id=rec.incident.id, request_id=req.id,
                                  runbook=req.runbook, host=req.host, required=req.requirement.required,
                                  roles=list(req.requirement.roles), code=v.code.value)
                self._audit_votes(req)
                if req.status == "approved":
                    self._audit_resolved(req)
                    if self._execute(rec, step) and step.status == "verifying":
                        return
                    continue
                if req.status in ("rejected", "expired"):
                    self._audit_resolved(req)
                    self._deny_step(rec, step, Verdict(Decision.DENY, f"approval {req.status}",
                                                       Reason.APPROVAL_REJECTED if req.status == "rejected"
                                                       else Reason.APPROVAL_TIMEOUT))
                    return
                step.status = "awaiting_approval"
                return
            if not self._execute(rec, step) or step.status == "verifying":
                return

    def _merge(self, old: IncidentRecord, group: IncidentRecord) -> None:
        """Fold a standalone host record into a group record: its remaining plan stops, no page."""
        old.merged_into = group.incident.id
        old.plan_aborted = True
        for s in old.steps:
            if s.status == "pending":
                s.status = "skipped"
            elif s.status == "awaiting_approval" and s.request_id:
                self.approvals.withdraw(s.request_id, self.fleet.tick)
                s.status = "skipped"
        group.executed.extend(old.executed)
        self.audit.append("merged", tick=self.fleet.tick, id=old.incident.id, into=group.incident.id)

    def _deny_step(self, rec: IncidentRecord, step: PlanStep, v: Verdict) -> None:
        """A non-transient denial stops the plan: later steps assume the earlier ones happened."""
        step.verdict, step.status = v, "denied"
        rec.denied.append(f"{step.proposal.runbook}@{step.proposal.host}")
        self._abort_plan(rec, f"{step.proposal.runbook}@{step.proposal.host} denied ({v.code.value})")

    def _abort_plan(self, rec: IncidentRecord, reason: str) -> None:
        rec.plan_aborted = True
        skipped = 0
        for s in rec.steps:
            if s.status == "pending":
                s.status, skipped = "skipped", skipped + 1
            elif s.status == "awaiting_approval" and s.request_id:
                if self.approvals.withdraw(s.request_id, self.fleet.tick):
                    self.audit.append("approval_resolved", tick=self.fleet.tick, id=rec.incident.id,
                                      request_id=s.request_id, runbook=s.proposal.runbook, host=s.proposal.host,
                                      status="withdrawn", required=0, approvers=[])
                s.status, skipped = "skipped", skipped + 1
        self.audit.append("plan_aborted", tick=self.fleet.tick, id=rec.incident.id, reason=reason, skipped=skipped)
        self._page(rec, f"plan stopped: {reason}")

    def _execute(self, rec: IncidentRecord, step: PlanStep) -> bool:
        """Apply the runbook (unless dry-run). Returns False if the step was denied at execution time."""
        p = step.proposal
        if step.request_id is not None:
            v = self.policy.evaluate(p.runbook, p.host)  # re-check: fleet state may have changed while waiting
            if v.decision == Decision.DENY:
                self._audit_policy(rec, step, v, phase="recheck")
                if v.code in TRANSIENT_DENIALS and step.waits < MAX_STEP_WAIT:
                    step.waits += 1
                    step.status = "approved_waiting"
                    return False
                self._deny_step(rec, step, v)
                return False
        rb = CATALOG[p.runbook]
        result = rb.apply(self.fleet, p.host, dry_run=self.dry_run)
        step.hosts = result.hosts
        step.executed_tick = self.fleet.tick
        self.policy.record(p.runbook, p.host, result.hosts)
        self.executed.append((self.fleet.tick, p.runbook, p.host))
        rec.executed.append(f"{p.runbook}@{p.host}")
        self.audit.append("executed", tick=self.fleet.tick, id=rec.incident.id, runbook=p.runbook, host=p.host,
                          hosts=result.hosts, changes=result.changes[:20], dry_run=self.dry_run,
                          request_id=step.request_id, rollback=step.is_rollback, tier=rb.tier.name)
        if rb.verify and not self.dry_run:
            step.status = "verifying"
            step.verify_at = self.verifier.due_at(rb, self.fleet.tick)
        else:
            step.status = "verified"
        return True

    # ---- approvals ---------------------------------------------------------------------------
    def _poll_approvals(self) -> None:
        resolved, paged, changed = self.approvals.poll(self.fleet.tick)
        for req in changed:
            self._audit_votes(req, only_tick=self.fleet.tick)
        for req in paged:
            rec, _ = self._step_by_request[req.id]
            self._page(rec, f"approval for {req.runbook}@{req.host} unanswered for {self.approvals.page_after} ticks")
        for req in resolved:
            self._audit_resolved(req)
            rec, step = self._step_by_request[req.id]
            if req.status == "approved":
                step.status = "approved_waiting"
                self._execute(rec, step)
            elif req.status != "withdrawn":
                v = Verdict(Decision.DENY, f"approval {req.status}",
                            Reason.APPROVAL_TIMEOUT if req.status == "expired" else Reason.APPROVAL_REJECTED)
                self._audit_policy(rec, step, v, phase="approval")
                self._deny_step(rec, step, v)
        # approved steps that hit a transient denial at execution time are retried here each tick
        for rec in list(self.records.values()):
            for step in rec.steps:
                if step.status == "approved_waiting" and not rec.plan_aborted:
                    self._execute(rec, step)

    def _audit_votes(self, req: ApprovalRequest, only_tick: int | None = None) -> None:
        for a in req.approvals:
            if only_tick is not None and a.tick != only_tick:
                continue
            self.audit.append("approval", tick=a.tick, id=req.incident_id, request_id=req.id, runbook=req.runbook,
                              host=req.host, approver=a.approver, role=a.role, approved=a.approved)

    def _audit_resolved(self, req: ApprovalRequest) -> None:
        self.audit.append("approval_resolved", tick=self.fleet.tick, id=req.incident_id, request_id=req.id,
                          runbook=req.runbook, host=req.host, status=req.status, required=req.requirement.required,
                          approvers=sorted(req.valid_approvers()))

    # ---- verification ------------------------------------------------------------------------
    def _run_verifications(self) -> None:
        t = self.fleet.tick
        for rec in list(self.records.values()):
            for step in list(rec.steps):
                if step.status != "verifying" or step.verify_at is None or t < step.verify_at:
                    continue
                p = step.proposal
                v = self.verifier.verify(p.runbook, p.host, step.hosts)
                self.audit.append("verify", tick=t, id=rec.incident.id, runbook=p.runbook, host=p.host, ok=v.ok,
                                  failed=v.failed[:5])
                self.policy.report_verification(p.runbook, p.host, v.ok)
                if v.ok:
                    step.status = "verified"
                    continue
                step.status = "failed"
                rec.verify_failures += 1
                for s in rec.steps:
                    if s.status == "pending":
                        s.status = "skipped"
                if v.rollback is not None and not step.is_rollback:
                    rb_step = PlanStep(v.rollback, is_rollback=True)
                    rec.steps.append(rb_step)
                    vd = self.policy.evaluate(v.rollback.runbook, v.rollback.host)
                    rb_step.verdict = vd
                    self._audit_policy(rec, rb_step, vd, phase="rollback")
                    if vd.decision == Decision.ALLOW:
                        if self._execute(rec, rb_step):
                            rec.rollbacks.append(f"{v.rollback.runbook}@{v.rollback.host}")
                            step.status = "rolled_back"
                    elif vd.decision == Decision.NEEDS_APPROVAL:
                        self._advance_plan(rec)  # submits the approval request for the rollback step
                    else:
                        rb_step.status = "denied"
                        rec.denied.append(f"{v.rollback.runbook}@{v.rollback.host}")
                self._abort_plan(rec, f"verification of {p.runbook}@{p.host} failed: {v.failed[0]}")

    # ---- bookkeeping -------------------------------------------------------------------------
    def _audit_policy(self, rec: IncidentRecord, step: PlanStep, v: Verdict, phase: str = "execute",
                      provisional: bool = False) -> None:
        p = step.proposal
        self.audit.append("policy", tick=self.fleet.tick, id=rec.incident.id, runbook=p.runbook, host=p.host,
                          decision=v.decision.value, code=v.code.value, reason=v.reason, rationale=p.rationale[:200],
                          phase=phase, rollback=step.is_rollback, provisional=provisional)

    def _page(self, rec: IncidentRecord, reason: str) -> None:
        rec.escalated = True
        if rec.paged_tick is None:
            rec.paged_tick = self.fleet.tick
        page = {"tick": self.fleet.tick, "incident": rec.incident.id, "reason": reason}
        self.pages.append(page)
        self.audit.append("page", tick=self.fleet.tick, id=rec.incident.id, reason=reason)

    def _faults_of(self, rec: IncidentRecord) -> set[str]:
        if rec.is_group:
            g: GroupIncident = rec.incident  # type: ignore[assignment]
            return set(g.signal.split("+")) | {m.signal for m in g.members}
        return {rec.incident.signal}

    def _update_status(self) -> None:
        t = self.fleet.tick
        for rec in self.records.values():
            if rec.status == "resolved":
                continue
            hosts = [self.fleet.hosts[h] for h in rec.hosts if h in self.fleet.hosts]
            faults = self._faults_of(rec)
            still = [h for h in hosts if any(f in h.faults for f in faults)]
            if not still:
                rec.status, rec.closed_tick = "resolved", t
                self.audit.append("closed", tick=t, id=rec.incident.id, status="resolved",
                                  mttr=t - rec.incident.opened_tick)
            elif rec.status == "open" and all(not h.active for h in still):
                rec.status, rec.contained_tick, rec.closed_tick = "contained", t, t
                self.audit.append("closed", tick=t, id=rec.incident.id, status="contained",
                                  mttr=t - rec.incident.opened_tick)

    def snapshot(self) -> dict[str, Any]:
        t = self.fleet.tick
        return {"tick": t, "load": round(self.fleet.load.factor(t), 3), "hosts": len(self.fleet.hosts),
                "active": sum(h.active for h in self.fleet.hosts.values()),
                "drained": sum(not h.active for h in self.fleet.hosts.values()),
                "faulty": len(self.fleet.faulty_hosts()),
                "open": sum(r.status == "open" for r in self.records.values()),
                "resolved": sum(r.status == "resolved" for r in self.records.values()),
                "contained": sum(r.status == "contained" for r in self.records.values()),
                "pending_approvals": len(self.approvals.pending()),
                "executed_this_tick": [(rb, h) for tk, rb, h in self.executed if tk == t],
                "pages": len(self.pages)}

    def summary(self) -> dict[str, Any]:
        recs = list(self.records.values())
        resolved = [r for r in recs if r.status == "resolved"]
        mttr = [r.closed_tick - r.incident.opened_tick for r in resolved if r.closed_tick is not None]
        return {"ticks": self.fleet.tick, "hosts": len(self.fleet.hosts), "incidents": len(recs),
                "resolved": len(resolved), "contained": sum(r.status == "contained" for r in recs),
                "open": sum(r.status == "open" for r in recs), "executed": len(self.executed),
                "denied": sum(len(r.denied) for r in recs), "pages": len(self.pages),
                "approvals": {s: sum(1 for r in self.approvals.requests.values() if r.status == s)
                              for s in ("approved", "rejected", "expired", "withdrawn", "pending")},
                "verify_failures": sum(r.verify_failures for r in recs),
                "rollbacks": sum(len(r.rollbacks) for r in recs),
                "mttr_mean": round(sum(mttr) / len(mttr), 2) if mttr else None,
                "drained_fraction": round(self.fleet.drained_fraction(), 3),
                "decisions": dict(self.policy.decisions), "audit_entries": len(self.audit.entries),
                "audit_ok": self.audit.verify()[0], "dry_run": self.dry_run}
