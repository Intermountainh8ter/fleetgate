"""PostmortemAgent: a structured postmortem built from the audit log alone.

The timeline, metrics and action items are derived deterministically from audit entries. An LLM,
when present, may only write the narrative summary; the template fallback is always available.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .llm import LLM, safe_complete


@dataclass
class Postmortem:
    incident_id: str
    title: str
    severity: str | None
    hosts: list[str]
    detected_tick: int | None
    first_action_tick: int | None
    closed_tick: int | None
    status: str
    mttr_ticks: int | None
    root_cause: str | None
    contributing: list[str]
    timeline: list[dict[str, Any]]
    actions_executed: list[str]
    actions_denied: list[dict[str, Any]]
    approvals: list[dict[str, Any]]
    verifications: list[dict[str, Any]]
    rollbacks: list[str]
    pages: int
    action_items: list[str]
    summary: str = ""
    contained_tick: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def markdown(self) -> str:
        lines = [f"# Postmortem: {self.title}", "",
                 f"- Incident: `{self.incident_id}`", f"- Severity: {self.severity or 'n/a'}",
                 f"- Hosts: {', '.join(self.hosts) or 'n/a'}", f"- Status: {self.status}",
                 f"- Detected: tick {self.detected_tick}; first action: tick {self.first_action_tick}; "
                 f"contained: tick {self.contained_tick}; closed: tick {self.closed_tick}; "
                 f"MTTR: {self.mttr_ticks if self.mttr_ticks is not None else 'n/a'} ticks",
                 f"- Root cause: {self.root_cause or 'undetermined'}",
                 f"- Contributing: {', '.join(self.contributing) or 'none recorded'}", "",
                 "## Summary", "", self.summary, "", "## Timeline", ""]
        lines += [f"- t={e['tick']}: {e['event']}" for e in self.timeline]
        denied = ", ".join("{runbook}@{host} ({code})".format(**d) for d in self.actions_denied) or "none"
        lines += ["", "## Actions", "",
                  f"- Executed: {', '.join(self.actions_executed) or 'none'}",
                  f"- Denied by policy: {denied}",
                  f"- Approvals: {len(self.approvals)} requested, "
                  f"{sum(1 for a in self.approvals if a['status'] == 'approved')} approved",
                  f"- Verifications: {sum(1 for v in self.verifications if v['ok'])}/{len(self.verifications)} passed",
                  f"- Rollbacks: {', '.join(self.rollbacks) or 'none'}", f"- Pages: {self.pages}", "",
                  "## Action items", ""]
        lines += [f"- [ ] {a}" for a in self.action_items] or ["- none"]
        return "\n".join(lines) + "\n"


class PostmortemAgent:
    def __init__(self, llm: LLM | None = None):
        self.llm = llm

    def incident_ids(self, entries: list[dict[str, Any]]) -> list[str]:
        return [e["id"] for e in entries if e["kind"] in ("incident", "group_incident")]

    def write(self, entries: list[dict[str, Any]], incident_id: str) -> Postmortem:
        rel = [e for e in entries if e.get("id") == incident_id or e.get("incident_id") == incident_id]
        opened = next((e for e in rel if e["kind"] in ("incident", "group_incident")), None)
        if opened is None:
            raise KeyError(f"incident {incident_id!r} not in audit log")
        hosts = list(opened.get("hosts") or [opened.get("host")])
        signal = opened.get("signal") or opened.get("hypothesis") or "incident"
        severity = next((e.get("severity") for e in rel if e["kind"] == "triage"), None)
        rc = next((e for e in rel if e["kind"] == "root_cause"), None)
        closes = [e for e in rel if e["kind"] == "closed"]
        closed = closes[-1] if closes else None  # an incident can be contained first and resolved later
        contained = next((e for e in closes if e.get("status") == "contained"), None)
        executed = [e for e in rel if e["kind"] == "executed"]
        denied = [{"runbook": e["runbook"], "host": e["host"], "code": e.get("code")}
                  for e in rel if e["kind"] == "policy" and e.get("decision") == "DENY" and not e.get("provisional")]
        req_ids = {e["request_id"] for e in rel if e["kind"] == "approval_request"}
        approvals = [{"request_id": e["request_id"], "runbook": e.get("runbook"), "host": e.get("host"),
                      "status": e.get("status")} for e in entries
                     if e["kind"] == "approval_resolved" and e.get("request_id") in req_ids]
        verifications = [{"runbook": e["runbook"], "host": e["host"], "ok": e["ok"], "failed": e.get("failed", [])}
                         for e in rel if e["kind"] == "verify"]
        rollbacks = [f"{e['runbook']}@{e['host']}" for e in executed if e.get("rollback")]
        pages = sum(1 for e in rel if e["kind"] == "page")
        detected = opened.get("tick")
        first_action = executed[0]["tick"] if executed else None
        closed_tick = closed.get("tick") if closed else None
        status = closed.get("status") if closed else "open"
        resolved = closed_tick is not None and detected is not None and status == "resolved"
        mttr = (closed_tick - detected) if resolved else None
        timeline = [{"tick": e.get("tick", detected), "event": _describe(e)} for e in rel if e["kind"] != "checkpoint"]
        items = _action_items(signal, status, denied, approvals, verifications, pages, rc)
        pm = Postmortem(incident_id, f"{signal} on {', '.join(hosts[:3])}{'...' if len(hosts) > 3 else ''}",
                        severity, hosts, detected, first_action, closed_tick, status, mttr,
                        rc.get("hypothesis") if rc else None, list(rc.get("contributing", [])) if rc else [],
                        timeline, [f"{e['runbook']}@{e['host']}" for e in executed], denied, approvals,
                        verifications, rollbacks, pages, items)
        pm.contained_tick = contained.get("tick") if contained else None
        pm.summary = self._summary(pm)
        return pm

    def _summary(self, pm: Postmortem) -> str:
        template = (f"{pm.title} was detected at tick {pm.detected_tick} with severity {pm.severity or 'n/a'}. "
                    f"Root cause: {pm.root_cause or 'undetermined'}. "
                    f"{len(pm.actions_executed)} action(s) executed, {len(pm.actions_denied)} denied by policy, "
                    f"{pm.pages} page(s). Final status: {pm.status}"
                    f"{f' after {pm.mttr_ticks} ticks' if pm.mttr_ticks is not None else ''}.")
        if not self.llm:
            return template
        facts = {k: v for k, v in pm.to_dict().items() if k not in ("timeline", "summary")}
        out = safe_complete(self.llm, "You are writing the summary paragraph of an incident postmortem. Use only the "
                                      "facts given; no speculation, no new actions. Max 120 words.",
                            json.dumps(facts, default=str), template)
        return out[:1200] if len(out.split()) <= 160 else template


def _describe(e: dict[str, Any]) -> str:
    k = e["kind"]
    if k in ("incident", "group_incident"):
        return f"detected {e.get('signal') or e.get('hypothesis')} on {e.get('host') or e.get('scope_id')}"
    if k == "triage":
        return f"triaged as {e.get('severity')}: {e.get('summary', '')[:80]}"
    if k == "root_cause":
        return f"root cause hypothesis {e.get('hypothesis')} (confidence {e.get('confidence')})"
    if k == "policy":
        return f"gate {e.get('decision')} {e.get('runbook')}@{e.get('host')} [{e.get('code')}]"
    if k == "approval_request":
        return f"approval requested for {e.get('runbook')}@{e.get('host')} ({e.get('required')} of {e.get('roles')})"
    if k == "executed":
        return f"executed {e.get('runbook')}@{e.get('host')}{' (dry-run)' if e.get('dry_run') else ''}"
    if k == "verify":
        outcome = "ok" if e.get("ok") else "FAILED " + str(e.get("failed"))
        return f"verification of {e.get('runbook')}@{e.get('host')}: {outcome}"
    if k == "page":
        return f"PAGED: {e.get('reason')}"
    if k == "closed":
        return f"closed as {e.get('status')}"
    if k == "approval":
        return f"{e.get('approver')} ({e.get('role')}) {'approved' if e.get('approved') else 'rejected'} " \
               f"{e.get('runbook')}@{e.get('host')}"
    if k == "approval_resolved":
        return f"approval for {e.get('runbook')}@{e.get('host')} {e.get('status')}"
    if k == "plan":
        return f"plan of {e.get('n_steps')} step(s) proposed"
    if k == "plan_aborted":
        return f"plan stopped: {e.get('reason')}"
    if k == "merged":
        return f"merged into {e.get('into')}"
    if k == "escalation":
        return f"escalated: {e.get('reason')}"
    return k


def _action_items(signal: str, status: str, denied: list[dict[str, Any]], approvals: list[dict[str, Any]],
                  verifications: list[dict[str, Any]], pages: int, rc: dict[str, Any] | None) -> list[str]:
    items: list[str] = []
    if status == "contained":
        items.append(f"Hardware follow-up: {signal} is contained (host drained) but not fixed; "
                     "track the DC-ops ticket.")
    if status == "open":
        items.append("Incident still open at end of log: confirm current state before closing.")
    codes = {d["code"] for d in denied}
    if "DENY_COOLDOWN" in codes:
        items.append("Planner re-proposed an action inside cooldown: check playbook ordering.")
    if "DENY_BLAST_RADIUS" in codes or "DENY_ROLE_CAPACITY_FLOOR" in codes:
        items.append("Blast-radius cap was hit: review spare capacity (see CapacityAgent report).")
    if "DENY_PRECONDITION_FAILED" in codes:
        items.append("A runbook was proposed before its preconditions held: review playbook sequencing.")
    if any(a["status"] in ("expired", "rejected") for a in approvals):
        items.append("Approval expired or was rejected: decide whether the policy or the plan was wrong.")
    if pages:
        items.append(f"{pages} page(s) fired waiting for approval: review approver coverage/on-call rota.")
    for v in verifications:
        if not v["ok"]:
            items.append(f"Verification of {v['runbook']} failed ({v['failed'][:1]}): "
                         "review probe thresholds or the runbook.")
    if rc and rc.get("contributing"):
        items.append(f"Address the upstream cause ({rc['hypothesis']}); {', '.join(rc['contributing'])} were symptoms.")
    return items
