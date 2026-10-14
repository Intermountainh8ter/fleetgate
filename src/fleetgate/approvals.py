"""Approval requests, N-of-M approver pools and escalation timers.

A NEEDS_APPROVAL verdict carries an `ApprovalRequirement` (how many distinct approvers, from which
roles). The queue collects `Approval` votes, pages when a request sits unanswered for
`page_after_ticks`, and expires it after `expire_after_ticks`. Approvers only ever answer a
request the policy gate has already issued; they cannot originate an action.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy import ApprovalRequirement


@dataclass(frozen=True)
class Approval:
    approver: str
    role: str
    approved: bool
    tick: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"approver": self.approver, "role": self.role, "approved": self.approved, "tick": self.tick,
                "note": self.note}


@dataclass
class ApprovalRequest:
    id: str
    incident_id: str
    runbook: str
    host: str
    rationale: str
    requirement: ApprovalRequirement
    opened_tick: int
    approvals: list[Approval] = field(default_factory=list)
    status: str = "pending"  # pending | approved | rejected | expired
    paged_tick: int | None = None
    resolved_tick: int | None = None

    def valid_approvers(self) -> set[str]:
        return set(self._valid_roles())

    def _valid_roles(self, extra: list[Approval] | None = None) -> dict[str, str]:
        return {a.approver: a.role for a in [*self.approvals, *(extra or [])]
                if a.approved and a.role in self.requirement.roles}

    def satisfied(self, extra: list[Approval] | None = None) -> bool:
        return self.requirement.satisfied_by(self._valid_roles(extra))

    def rejected(self) -> bool:
        return any(not a.approved for a in self.approvals)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "incident_id": self.incident_id, "runbook": self.runbook, "host": self.host,
                "requirement": self.requirement.to_dict(), "opened_tick": self.opened_tick, "status": self.status,
                "approvals": [a.to_dict() for a in self.approvals], "paged_tick": self.paged_tick,
                "resolved_tick": self.resolved_tick}


class Approver(Protocol):
    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        """Return new votes for this request (possibly none: the request stays pending)."""
        ...


class AutoApprover:
    """`approve` votes with every required role at once; `deny` rejects; `hold` never answers."""

    def __init__(self, mode: str = "approve", name: str = "auto"):
        if mode not in ("approve", "deny", "hold"):
            raise ValueError(mode)
        self.mode, self.name = mode, name

    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        if self.mode == "hold":
            return []
        if self.mode == "deny":
            return [Approval(f"{self.name}-{request.requirement.roles[0]}", request.requirement.roles[0], False, tick,
                             "auto-deny")]
        out: list[Approval] = []
        for role in request.requirement.roles:
            if request.satisfied(out):
                break
            if f"{self.name}-{role}" in {a.approver for a in request.approvals}:
                continue
            out.append(Approval(f"{self.name}-{role}", role, True, tick, "auto-approve"))
        return out


class ScriptedApprover:
    """Deterministic approver for tests: a list of (approver, role, approved) answered after `delay` ticks."""

    def __init__(self, votes: list[tuple[str, str, bool]], delay: int = 0):
        self.votes, self.delay = list(votes), delay
        self.seen: dict[str, int] = {}

    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        self.seen.setdefault(request.id, tick)
        if tick - self.seen[request.id] < self.delay:
            return []
        given = {a.approver for a in request.approvals}
        return [Approval(a, r, ok, tick, "scripted") for a, r, ok in self.votes if a not in given]


class InteractiveApprover:
    """Prompts a human on stdin for each role until the requirement is met (used by the CLI)."""

    def __init__(self, input_fn: Callable[[str], str] = input, output_fn: Callable[[str], None] = print,
                 operator: str = "operator"):
        self.input_fn, self.output_fn, self.operator = input_fn, output_fn, operator

    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        req = request.requirement
        self.output_fn(f"[tick {tick}] approval needed: {request.runbook} on {request.host} "
                       f"({req.code.value}; {req.required} of {', '.join(req.roles)})\n"
                       f"  rationale: {request.rationale}")
        out: list[Approval] = []
        for role in req.roles:
            if request.satisfied(out):
                break
            ans = self.input_fn(f"  approve as {role}? [y/N/h(old)] ").strip().lower()
            if ans == "h":
                return out
            if ans == "y":
                out.append(Approval(f"{self.operator}-{role}", role, True, tick, "interactive"))
            else:
                out.append(Approval(f"{self.operator}-{role}", role, False, tick, "interactive"))
                return out
        return out


class LegacyApprover:
    """Adapts the original `(proposal, reason) -> bool` callback to the N-of-M protocol."""

    def __init__(self, fn: Callable[[Any, str], bool]):
        self.fn = fn

    def review(self, request: ApprovalRequest, tick: int) -> list[Approval]:
        from .agents import Proposal  # local import to avoid a cycle

        ok = bool(self.fn(Proposal(request.runbook, request.host, request.rationale), request.requirement.code.value))
        return AutoApprover("approve" if ok else "deny", "legacy").review(request, tick)


def as_approver(obj: Any) -> Approver:
    if obj is None:
        return AutoApprover("deny")
    if hasattr(obj, "review"):
        return obj
    if callable(obj):
        try:
            n = len(inspect.signature(obj).parameters)
        except (TypeError, ValueError):
            n = 2
        if n == 2:
            return LegacyApprover(obj)
    raise TypeError(f"not an approver: {obj!r}")


class ApprovalQueue:
    def __init__(self, approver: Approver, page_after_ticks: int = 3, expire_after_ticks: int = 12):
        self.approver = approver
        self.page_after, self.expire_after = page_after_ticks, expire_after_ticks
        self.requests: dict[str, ApprovalRequest] = {}
        self._n = 0

    def submit(self, incident_id: str, runbook: str, host: str, rationale: str, requirement: ApprovalRequirement,
               tick: int) -> ApprovalRequest:
        self._n += 1
        req = ApprovalRequest(f"apr-{self._n:04d}", incident_id, runbook, host, rationale, requirement, tick)
        self.requests[req.id] = req
        self._poll_one(req, tick)
        return req

    def _poll_one(self, req: ApprovalRequest, tick: int) -> list[Approval]:
        if req.status != "pending":
            return []
        new = [a for a in self.approver.review(req, tick) if a.approver not in {x.approver for x in req.approvals}]
        req.approvals.extend(new)
        if req.rejected():
            req.status, req.resolved_tick = "rejected", tick
        elif req.satisfied():
            req.status, req.resolved_tick = "approved", tick
        elif tick - req.opened_tick >= self.expire_after:
            req.status, req.resolved_tick = "expired", tick
        return new

    def poll(self, tick: int) -> tuple[list[ApprovalRequest], list[ApprovalRequest], list[ApprovalRequest]]:
        """Advance every pending request. Returns (newly resolved, newly paged, votes-changed)."""
        resolved, paged, changed = [], [], []
        for req in self.requests.values():
            if req.status != "pending":
                continue
            new = self._poll_one(req, tick)
            if new:
                changed.append(req)
            if req.status != "pending":
                resolved.append(req)
            elif req.paged_tick is None and tick - req.opened_tick >= self.page_after:
                req.paged_tick = tick
                paged.append(req)
        return resolved, paged, changed

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self.requests.values() if r.status == "pending"]

    def withdraw(self, request_id: str, tick: int) -> bool:
        req = self.requests.get(request_id)
        if req is None or req.status != "pending":
            return False
        req.status, req.resolved_tick = "withdrawn", tick
        return True
