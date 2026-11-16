"""Approval-collusion driver: queue trusts self-declared roles; a roster check closes the forged-role gap."""
from fleetgate.approval_collusion import ROSTER, RosterApprover, requirement, simulate
from fleetgate.approvals import ApprovalQueue, ScriptedApprover


def test_deterministic():
    assert simulate(3, 40) == simulate(3, 40)


def test_requirement_has_three_slots():
    assert requirement().required == 3


def test_attack_arms_without_roster():
    r = simulate(5, 100)
    rates = r["approval_bypass_rate"]
    assert rates["duplicate_name"] == 0.0
    assert rates["wrong_role_sybil"] == 0.0
    assert rates["forged_role_sybil"] == 1.0
    assert r["honest_approval_rate"]["no_roster"] == 1.0


def test_roster_closes_forged_and_admits_honest():
    r = simulate(5, 100)
    assert set(r["approval_bypass_rate_roster"].values()) == {0.0}
    assert r["honest_approval_rate"]["roster"] == 1.0
    assert r["all_logs_verify"] is True


def test_roster_drops_unregistered_vote():
    ap = RosterApprover(ScriptedApprover([("alice", "sre-lead", True), ("alice", "dc-ops", True)]), ROSTER)
    req = ApprovalQueue(ap).submit("i", "wipe_disk", "h", "x", requirement(), 0)
    assert [a.role for a in req.approvals] == ["sre-lead"]
