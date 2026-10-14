"""Targeted tests for defensive paths: pending approvals on merge/abort, resealed-log forgeries, odd callables."""
import copy

from helpers import first_host

from fleetgate import Fleet, Orchestrator
from fleetgate.approvals import (
    Approval,
    ApprovalQueue,
    ApprovalRequest,
    AutoApprover,
    LegacyApprover,
    ScriptedApprover,
    as_approver,
)
from fleetgate.audit import AuditLog, merkle_root
from fleetgate.dashboard import render_tick
from fleetgate.orchestrator import Orchestrator as Orch
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import ApprovalRequirement, Decision, Reason, Verdict
from fleetgate.postmortem import PostmortemAgent, _action_items, _describe
from fleetgate.runner import run_scenario
from fleetgate.scenarios import Scenario

REQ = ApprovalRequirement(1, ("sre",), Reason.DISRUPTIVE_TIER)


# ---- orchestrator ---------------------------------------------------------------------------------------


def protected_rack_fleet():
    """A fleet whose first rack contains a protected host: rack-wide actions there need protected approval."""
    f = Fleet(30, seed=2)
    rack = next(r for r in f.topology.racks.values() if any(f.hosts[h].role == "db-primary" for h in r.hosts))
    return f, [h for h in rack.hosts if f.hosts[h].role not in ("db-primary", "validator")]


def test_merging_into_a_group_withdraws_a_pending_approval_of_the_absorbed_incident():
    f, hosts = protected_rack_fleet()
    for h in hosts[:2]:
        f.inject(h, "uplink_loss")
    o = Orchestrator(f, approver=AutoApprover("hold"))
    o.run(2)
    pending = [r for r in o.approvals.requests.values() if r.status == "pending"]
    assert pending and pending[0].runbook == "failover_tor_uplink"  # rack action touching a protected host
    f.inject(hosts[2], "uplink_loss")
    o.run(3)
    merged = [r for r in o.records.values() if r.merged_into]
    assert merged and all(not r.active for r in merged)
    assert any(r.status == "withdrawn" for r in o.approvals.requests.values())
    assert all(s.status in ("skipped", "denied", "verified", "failed") for r in merged for s in r.steps)


def test_aborting_a_plan_withdraws_the_request_it_was_waiting_on():
    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "disk_failing")
    o = Orchestrator(f, approver=AutoApprover("hold"))
    o.run(12)
    rec = next(iter(o.records.values()))
    waiting = next(s for s in rec.steps if s.status == "awaiting_approval")
    o._abort_plan(rec, "operator cancelled")
    assert waiting.status == "skipped"
    assert o.approvals.requests[waiting.request_id].status == "withdrawn"
    assert [e for e in o.audit.entries if e["kind"] == "approval_resolved" and e["status"] == "withdrawn"]
    assert not rec.active


def test_a_gate_verdict_that_needs_approval_but_names_no_requirement_fails_closed(monkeypatch):
    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "service_down")
    o = Orchestrator(f, approver=approve_all)
    no_requirement = Verdict(Decision.NEEDS_APPROVAL, "x", Reason.DISRUPTIVE_TIER)
    monkeypatch.setattr(o.policy, "evaluate", lambda rb, h: no_requirement)
    o.run(6)
    assert o.executed == []
    rec = next(iter(o.records.values()))
    assert rec.denied and any("approval required but no requirement" in e["reason"] or "INTERNAL_ERROR" in e["reason"]
                              for e in o.audit.entries if e["kind"] == "plan_aborted")


def test_partial_votes_are_audited_once_per_tick():
    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "disk_failing")
    sa = ScriptedApprover([("alice", "sre-lead", True), ("bob", "dc-ops", True)])

    class Staggered(ScriptedApprover):
        def review(self, request, tick):
            order = [v for v in self.votes if v[0] not in {a.approver for a in request.approvals}]
            return [Approval(a, r, ok, tick, "s") for a, r, ok in order[:1]]

    o = Orchestrator(f, approver=Staggered(sa.votes))
    o.run(25)
    votes = [e for e in o.audit.entries if e["kind"] == "approval"]
    assert [v["approver"] for v in votes] == ["alice", "bob"] and votes[0]["tick"] < votes[1]["tick"]
    assert next(iter(o.records.values())).status == "resolved"


# ---- approvals ------------------------------------------------------------------------------------------


def test_auto_approver_does_not_vote_twice_and_uninspectable_callables_are_legacy():
    two = ApprovalRequirement(2, ("sre", "sre-lead"), Reason.DISRUPTIVE_TIER)
    req = ApprovalRequest("a", "i", "x", "h", "", two, 0)
    ap = AutoApprover("approve", "bot")
    req.approvals.append(Approval("bot-sre", "sre", True, 0))
    out = ap.review(req, 1)
    assert [a.approver for a in out] == ["bot-sre-lead"]
    assert isinstance(as_approver(int), LegacyApprover)  # no inspectable signature: assume (proposal, reason)
    q = ApprovalQueue(AutoApprover("approve"))
    r = q.submit("i", "x", "h", "", REQ, 0)
    assert q._poll_one(r, 5) == []  # already resolved: nothing to do


# ---- audit: forgeries that survive the hash chain but not the checkpoint checks -----------------------------


def reseal(entries):
    """Recompute prev/hash for edited entries (what an attacker without the key can do)."""
    prev = AuditLog.GENESIS
    out = copy.deepcopy(entries)
    for e in out:
        e["prev"] = prev
        body = {k: v for k, v in e.items() if k not in ("prev", "hash", "sig")}
        e["hash"] = AuditLog._digest(prev, body)
        prev = e["hash"]
    log = AuditLog(checkpoint_every=0)
    log.entries = out
    return log


def logged(n=12):
    a = AuditLog(checkpoint_every=4)
    for i in range(n):
        a.append("evt", n=i)
    return a


def test_resealed_logs_still_fail_the_checkpoint_checks():
    base = logged()
    cps = [i for i, e in enumerate(base.entries) if e["kind"] == "checkpoint"]
    bad_root = copy.deepcopy(base.entries)
    bad_root[cps[0]]["merkle_root"] = merkle_root(["x"])
    r = reseal(bad_root).verify_full()
    assert not r.ok and "merkle root mismatch" in r.problems[0]
    bad_block = copy.deepcopy(base.entries)
    bad_block[cps[1]]["block_start"] = 0
    bad_block[cps[1]]["merkle_root"] = merkle_root([e["hash"] for e in base.entries[0:cps[1]]])
    r = reseal(bad_block).verify_full()
    assert not r.ok and "checkpoint covers wrong block" in r.problems[0]
    bad_chain = copy.deepcopy(base.entries)
    bad_chain[cps[1]]["prev_root"] = "0" * 64
    r = reseal(bad_chain).verify_full()
    assert not r.ok and "checkpoint chain broken" in r.problems[0]
    assert reseal(base.entries).verify_full().ok  # sanity: an untouched reseal is valid
    assert "unchecked_signatures" in r.to_dict()


# ---- postmortem -----------------------------------------------------------------------------------------


def test_action_items_cover_every_denial_family():
    denied = [{"code": c} for c in ("DENY_COOLDOWN", "DENY_BLAST_RADIUS", "DENY_PRECONDITION_FAILED")]
    items = "\n".join(_action_items("x", "resolved", denied, [], [], 0, None))
    assert "inside cooldown" in items and "Blast-radius cap" in items and "preconditions" in items
    assert "Blast-radius cap" in "\n".join(_action_items("x", "resolved", [{"code": "DENY_ROLE_CAPACITY_FLOOR"}],
                                                         [], [], 0, None))


def test_describe_covers_miscellaneous_audit_kinds():
    assert _describe({"kind": "plan_aborted", "reason": "r"}) == "plan stopped: r"
    assert _describe({"kind": "merged", "into": "g"}) == "merged into g"
    assert _describe({"kind": "escalation", "reason": "r"}) == "escalated: r"
    assert _describe({"kind": "run_start"}) == "run_start"
    entries = [{"kind": "incident", "id": "i", "tick": 1, "host": "h1", "signal": "x"},
               {"kind": "escalation", "id": "i", "tick": 1, "reason": "invalid plan"},
               {"kind": "merged", "id": "i", "tick": 2, "into": "g"}]
    pm = PostmortemAgent().write(entries, "i")
    assert pm.status == "open" and [t["event"] for t in pm.timeline][1:] == ["escalated: invalid plan", "merged into g"]


# ---- dashboard ------------------------------------------------------------------------------------------


def test_dashboard_lists_actions_executed_on_the_current_tick():
    scn = Scenario.from_dict({"name": "d", "fleet": {"hosts": 30, "seed": 5}, "ticks": 4,
                              "events": [{"tick": 2, "type": "inject", "host": {"role": "worker", "nth": 0},
                                          "fault": "disk_failing"}]})
    r = run_scenario(scn, approver=deny_all)
    assert "executed this tick: drain_host@" in render_tick(r.orchestrator)


def test_orchestrator_alias_is_the_same_class():
    assert Orch is Orchestrator
