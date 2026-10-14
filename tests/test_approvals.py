import pytest

from fleetgate.agents import Proposal
from fleetgate.approvals import (
    Approval,
    ApprovalQueue,
    ApprovalRequest,
    AutoApprover,
    InteractiveApprover,
    LatencyApprover,
    LegacyApprover,
    ScriptedApprover,
    as_approver,
)
from fleetgate.policy import ApprovalRequirement, Reason

REQ2 = ApprovalRequirement(2, ("sre-lead", "dc-ops", "change-manager"), Reason.DESTRUCTIVE_TIER)
REQ1 = ApprovalRequirement(1, ("sre", "sre-lead"), Reason.DISRUPTIVE_TIER)


def queue(approver, req=REQ2, page=3, expire=12):
    q = ApprovalQueue(approver, page, expire)
    r = q.submit("inc-1", "replace_disk", "h001", "because", req, tick=10)
    return q, r


def test_request_ids_are_sequential_and_serialisable():
    q = ApprovalQueue(AutoApprover("hold"))
    a = q.submit("i", "x", "h1", "", REQ1, 0)
    b = q.submit("i", "y", "h2", "", REQ1, 0)
    assert (a.id, b.id) == ("apr-0001", "apr-0002")
    d = a.to_dict()
    assert d["status"] == "pending" and d["requirement"]["required"] == 1 and d["approvals"] == []


def test_auto_approver_modes():
    q, r = queue(AutoApprover("approve"))
    assert r.status == "approved" and len(r.valid_approvers()) == 2 and r.resolved_tick == 10
    assert {a.role for a in r.approvals} == {"sre-lead", "dc-ops"}  # stops as soon as N is met
    q, r = queue(AutoApprover("deny"))
    assert r.status == "rejected" and r.rejected() and not r.satisfied()
    q, r = queue(AutoApprover("hold"))
    assert r.status == "pending"
    with pytest.raises(ValueError):
        AutoApprover("maybe")


def test_n_of_m_needs_distinct_approvers_from_listed_roles():
    votes = [("alice", "sre-lead", True), ("alice", "dc-ops", True)]  # same person twice
    q, r = queue(ScriptedApprover(votes))
    assert r.status == "pending" and r.valid_approvers() == {"alice"}
    q, r = queue(ScriptedApprover([("alice", "sre-lead", True), ("bob", "janitor", True)]))
    assert r.status == "pending"  # janitor is not an allowed role: the vote is recorded but not counted
    assert len(r.approvals) == 2 and r.valid_approvers() == {"alice"}
    q, r = queue(ScriptedApprover([("alice", "sre-lead", True), ("bob", "change-manager", True)]))
    assert r.status == "approved" and r.valid_approvers() == {"alice", "bob"}


def test_any_rejection_rejects_even_after_approvals():
    votes = [("alice", "sre-lead", True), ("bob", "dc-ops", False), ("carol", "change-manager", True)]
    q, r = queue(ScriptedApprover(votes))
    assert r.status == "rejected"


def test_duplicate_votes_by_same_approver_are_ignored():
    sa = ScriptedApprover([("alice", "sre-lead", True)])
    q, r = queue(sa)
    q.poll(11)
    q.poll(12)
    assert len(r.approvals) == 1 and r.status == "pending"


def test_scripted_delay_models_a_slow_human():
    sa = ScriptedApprover([("alice", "sre-lead", True), ("bob", "dc-ops", True)], delay=2)
    q, r = queue(sa)
    assert r.status == "pending"
    resolved, paged, changed = q.poll(11)
    assert (resolved, paged, changed) == ([], [], [])
    resolved, paged, changed = q.poll(12)
    assert resolved == [r] and changed == [r] and r.status == "approved" and r.resolved_tick == 12


def test_escalation_pages_once_then_expires():
    q, r = queue(AutoApprover("hold"), page=3, expire=6)
    assert q.poll(11) == ([], [], []) and q.poll(12) == ([], [], [])
    resolved, paged, _ = q.poll(13)  # 3 ticks unanswered
    assert paged == [r] and r.paged_tick == 13 and resolved == []
    assert q.poll(14)[1] == [] and q.poll(15)[1] == []  # paged exactly once
    resolved, paged, _ = q.poll(16)
    assert resolved == [r] and r.status == "expired" and r.resolved_tick == 16
    assert q.pending() == [] and q.poll(17) == ([], [], [])


def test_withdraw_only_pending_requests():
    q, r = queue(AutoApprover("hold"))
    assert q.withdraw(r.id, 11) and r.status == "withdrawn" and r.resolved_tick == 11
    assert not q.withdraw(r.id, 12) and not q.withdraw("apr-9999", 12)
    q2, r2 = queue(AutoApprover("approve"))
    assert not q2.withdraw(r2.id, 11)


def test_interactive_approver_prompts_each_role_until_met():
    answers = iter(["y", "y"])
    out = []
    ia = InteractiveApprover(input_fn=lambda prompt: next(answers), output_fn=out.append, operator="ops")
    q, r = queue(ia)
    assert r.status == "approved" and {a.approver for a in r.approvals} == {"ops-sre-lead", "ops-dc-ops"}
    assert "approval needed: replace_disk on h001" in out[0] and "APPROVAL_DESTRUCTIVE_TIER" in out[0]


def test_interactive_approver_no_and_hold():
    q, r = queue(InteractiveApprover(input_fn=lambda p: "n", output_fn=lambda s: None))
    assert r.status == "rejected"
    q, r = queue(InteractiveApprover(input_fn=lambda p: "h", output_fn=lambda s: None))
    assert r.status == "pending" and r.approvals == []
    q, r = queue(InteractiveApprover(input_fn=lambda p: "  Y ", output_fn=lambda s: None), req=REQ1)
    assert r.status == "approved"
    q, r = queue(InteractiveApprover(input_fn=lambda p: "", output_fn=lambda s: None), req=REQ1)
    assert r.status == "rejected"  # empty answer defaults to no


def test_legacy_callable_adapter_and_as_approver():
    seen = []

    def cb(proposal, reason):
        seen.append((proposal, reason))
        return True

    q, r = queue(as_approver(cb))
    assert r.status == "approved" and isinstance(as_approver(cb), LegacyApprover)
    assert isinstance(seen[0][0], Proposal) and seen[0][0].runbook == "replace_disk"
    assert seen[0][1] == "APPROVAL_DESTRUCTIVE_TIER"
    assert as_approver(lambda p, r: False).review(
        ApprovalRequest("x", "i", "rb", "h", "", REQ1, 0), 0)[0].approved is False
    assert isinstance(as_approver(None), AutoApprover)
    sa = ScriptedApprover([])
    assert as_approver(sa) is sa
    with pytest.raises(TypeError):
        as_approver(lambda only_one: True)
    with pytest.raises(TypeError):
        as_approver(42)


def test_approval_to_dict_and_valid_approvers_ignore_rejections():
    a = Approval("alice", "sre-lead", False, 3, "no")
    assert a.to_dict() == {"approver": "alice", "role": "sre-lead", "approved": False, "tick": 3, "note": "no"}
    r = ApprovalRequest("x", "i", "rb", "h", "", REQ1, 0, approvals=[a])
    assert r.valid_approvers() == set() and r.rejected()


def test_stacked_requirement_needs_each_pool_filled_by_different_people():
    stacked = ApprovalRequirement.from_pools([(1, ("sre", "sre-lead")), (1, ("sre-lead", "db-owner"))],
                                             Reason.DISRUPTIVE_TIER)
    assert stacked.required == 2 and stacked.roles == ("sre", "sre-lead", "db-owner")
    assert not stacked.satisfied_by({"alice": "sre"})  # a plain sre cannot approve a protected host alone
    assert not stacked.satisfied_by({"alice": "sre-lead"})  # one sre-lead cannot fill both pools
    assert stacked.satisfied_by({"alice": "sre", "bob": "db-owner"})
    assert stacked.satisfied_by({"alice": "sre-lead", "bob": "sre-lead"})
    # matching, not greedy: carol must take the db-owner pool so that alice can fill the sre pool
    assert stacked.satisfied_by({"carol": "sre-lead", "alice": "sre", "bob": "sre"}) is True
    assert not stacked.satisfied_by({"alice": "sre", "bob": "sre"})
    assert not stacked.satisfied_by({})


def test_auto_and_interactive_approvers_fill_every_pool():
    stacked = ApprovalRequirement.from_pools([(2, ("sre-lead", "dc-ops")), (1, ("sre-lead", "db-owner"))],
                                             Reason.DESTRUCTIVE_TIER)
    q, r = queue(AutoApprover("approve"), req=stacked)
    assert r.status == "approved" and len(r.valid_approvers()) == 3
    answers = iter(["y"] * 5)
    q, r = queue(InteractiveApprover(input_fn=lambda p: next(answers), output_fn=lambda s: None), req=stacked)
    assert r.status == "approved" and {a.role for a in r.approvals} == {"sre-lead", "dc-ops", "db-owner"}


def test_requirement_to_dict_lists_pools_and_defaults_to_one_pool():
    assert REQ2.pools == ((2, ("sre-lead", "dc-ops", "change-manager")),)
    stacked = ApprovalRequirement.from_pools([(1, ("a",)), (1, ("b",))], Reason.PROTECTED_ROLE)
    assert stacked.to_dict()["pools"] == [{"required": 1, "roles": ["a"]}, {"required": 1, "roles": ["b"]}]


def test_latency_approver_models_slow_humans_and_stricter_policies_cost_more_ticks():
    q, r = queue(LatencyApprover(base_delay=2, per_vote=1), req=REQ2)  # opened at tick 10, needs two votes
    assert r.status == "pending"
    assert q.poll(11)[0] == []  # age 1: nobody has looked yet
    q.poll(12)  # age 2: first reviewer answers
    assert r.status == "pending" and len(r.approvals) == 1
    resolved, _, changed = q.poll(13)  # age 3: second reviewer answers
    assert resolved == [r] and r.status == "approved" and r.resolved_tick == 13 and changed == [r]
    q1, r1 = queue(LatencyApprover(base_delay=2, per_vote=1), req=REQ1)
    q1.poll(12)
    assert r1.status == "approved" and r1.resolved_tick == 12  # one approval is a tick faster than two


def test_latency_approver_deny_mode_and_validation():
    q, r = queue(LatencyApprover(base_delay=1, mode="deny"))
    assert r.status == "pending"
    q.poll(11)
    assert r.status == "rejected"
    with pytest.raises(ValueError):
        LatencyApprover(base_delay=-1)
    with pytest.raises(ValueError):
        LatencyApprover(per_vote=0)
    q0, r0 = queue(LatencyApprover(base_delay=0, per_vote=1), req=REQ2)
    assert r0.status == "pending" and len(r0.approvals) == 1  # zero base delay: first vote is immediate
