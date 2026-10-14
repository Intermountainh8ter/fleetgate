"""Orchestrator behaviour: sequencing, approvals, escalation, verification/rollback, dry-run, group incidents."""
import pytest
from helpers import first_host

from fleetgate import Fleet, Orchestrator
from fleetgate.agents import Proposal
from fleetgate.approvals import AutoApprover, ScriptedApprover
from fleetgate.orchestrator import MAX_ID_LEN, MAX_PLAN_STEPS, approve_all, deny_all, sanitise_proposals
from fleetgate.policy import Policy, PolicyConfig, Reason


class Fixed:
    """Planner test double: always proposes the given (runbook, host-or-None) steps for the incident host."""

    def __init__(self, *steps, host=None):
        self.steps, self.host = steps, host

    def plan(self, inc, triage):
        return [Proposal(rb, self.host or inc.host, "fixed") for rb in self.steps]


def run(fleet, planner=None, approver=deny_all, ticks=25, **kw):
    o = Orchestrator(fleet, planner=planner, approver=approver, **kw)
    o.run(ticks)
    return o


def kinds(o, kind):
    return [e for e in o.audit.entries if e["kind"] == kind]


# ---- sequencing and verification ----------------------------------------------------------------------


def test_plan_runs_one_verified_step_at_a_time(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    o = run(fleet30, approver=approve_all)
    ticks = [t for t, _, _ in o.executed]
    assert [r for _, r, _ in o.executed] == ["drain_host", "open_ticket", "replace_disk", "undrain_host"]
    assert ticks == sorted(ticks) and len(set(ticks)) == 4  # one per verification cycle, never in the same tick
    rec = next(iter(o.records.values()))
    assert rec.status == "resolved" and not fleet30.hosts[worker].drained and not fleet30.hosts[worker].faults
    assert all(s.status == "verified" for s in rec.steps)
    assert [e["ok"] for e in kinds(o, "verify")] == [True] * 4


def test_every_proposal_gets_an_audited_verdict_and_every_execution_follows_one(fleet30, worker):
    fleet30.inject(worker, "service_down")
    o = run(fleet30, ticks=10)
    execs = kinds(o, "executed")
    assert execs
    for e in execs:
        earlier = [p for p in o.audit.entries[:e["seq"]] if p["kind"] == "policy" and p["runbook"] == e["runbook"]
                   and p["host"] == e["host"] and p["decision"] == "ALLOW"]
        assert earlier, e


def test_dry_run_decides_and_audits_but_never_mutates(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    before = {h.id: (h.drained, h.ticketed, dict(h.faults)) for h in fleet30.hosts.values()}
    o = run(fleet30, approver=approve_all, ticks=20, dry_run=True)
    after = {h.id: (h.drained, h.ticketed, dict(h.faults)) for h in fleet30.hosts.values()}
    assert before == after and not fleet30.pending
    assert o.executed and all(e["dry_run"] for e in kinds(o, "executed"))
    assert o.summary()["dry_run"] is True and next(iter(o.records.values())).status == "open"


def test_verification_failure_rolls_back_pages_and_stops_the_plan(fleet30, worker):
    fleet30.inject(worker, "cooling_failure")
    o = run(fleet30, Fixed("set_fan_profile_max", "open_ticket"), approve_all, ticks=12)
    rec = o.records[next(i for i in o.records if "cooling_failure" in i)]
    assert [s.status for s in rec.steps] == ["rolled_back", "skipped", "verified"]
    assert rec.steps[2].is_rollback and rec.steps[2].proposal.runbook == "set_fan_profile_auto"
    assert rec.verify_failures == 1 and rec.rollbacks == [f"set_fan_profile_auto@{worker}"] and rec.escalated
    assert any("plan stopped" in p["reason"] for p in o.pages)
    assert kinds(o, "plan_aborted") and kinds(o, "verify")[0]["ok"] is False
    assert fleet30.hosts[worker].fan_profile == "auto"
    assert "open_ticket" not in [r for _, r, _ in o.executed]


def test_rollback_that_needs_approval_waits_for_it_and_is_not_withdrawn(fleet30):
    prim = first_host(fleet30, "db-primary")
    fleet30.inject(prim, "cooling_failure")
    sa = ScriptedApprover([("a", "sre-lead", True), ("b", "db-owner", True)], delay=2)
    o = run(fleet30, Fixed("set_fan_profile_max"), sa, ticks=18)
    rec = o.records[next(i for i in o.records if "cooling_failure" in i)]
    assert rec.steps[0].status == "rolled_back" and rec.steps[1].is_rollback
    assert rec.steps[1].status in ("verified", "failed") and rec.steps[1].request_id
    resolved = [e for e in kinds(o, "approval_resolved") if e["runbook"] == "set_fan_profile_auto"]
    assert resolved and resolved[0]["status"] == "approved"  # not "withdrawn"
    assert rec.rollbacks == [f"set_fan_profile_auto@{prim}"]
    assert [e["rollback"] for e in kinds(o, "executed")][:2] == [False, True]


def test_approved_step_hitting_a_transient_denial_does_not_let_later_steps_jump_the_queue(fleet30, worker):
    fleet30.inject(worker, "service_down")
    sa = ScriptedApprover([("alice", "sre", True)], delay=2)  # slow human: one DISRUPTIVE approval
    o = Orchestrator(fleet30, planner=Fixed("drain_host", "reboot_host", "open_ticket", "undrain_host"), approver=sa)

    def cool_down(orch):  # reboot_host lands in cooldown after the request was filed, before it is approved
        req = next(iter(orch.approvals.requests.values()), None)
        if req is not None and orch.fleet.tick == req.opened_tick + 1:
            orch.policy.recent[(worker, "reboot_host")] = orch.fleet.tick

    o.on_tick = cool_down
    o.run(25)
    order = [(t, r) for t, r, _ in o.executed]
    assert [r for _, r in order] == ["drain_host", "reboot_host", "open_ticket", "undrain_host"]
    (req,) = o.approvals.requests.values()
    t_reboot = next(t for t, r in order if r == "reboot_host")
    assert t_reboot > req.resolved_tick  # approved earlier, but executed only once the cooldown cleared
    assert any(e["phase"] == "recheck" and e["code"] == "DENY_COOLDOWN" for e in kinds(o, "policy"))
    assert t_reboot < next(t for t, r in order if r == "open_ticket")


# ---- approvals and escalation ---------------------------------------------------------------------------


def test_deny_all_contains_but_does_not_resolve_destructive_work(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    o = run(fleet30, approver=deny_all, ticks=20)
    rec = next(iter(o.records.values()))
    assert rec.status == "contained" and rec.escalated and rec.denied == [f"replace_disk@{worker}"]
    assert [r for _, r, _ in o.executed] == ["drain_host", "open_ticket"]
    assert o.summary()["approvals"]["rejected"] == 1
    assert kinds(o, "approval_resolved")[0]["status"] == "rejected"
    assert any(e["code"] == Reason.APPROVAL_REJECTED.value for e in kinds(o, "policy") if e["phase"] == "approval")


def test_unanswered_request_pages_then_expires_with_a_timeout_code(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    o = run(fleet30, approver=AutoApprover("hold"), ticks=30)
    rec = next(iter(o.records.values()))
    (req,) = o.approvals.requests.values()
    assert req.status == "expired" and req.paged_tick == req.opened_tick + 3
    assert req.resolved_tick == req.opened_tick + 12
    assert any("unanswered" in p["reason"] and p["tick"] == req.paged_tick for p in o.pages)
    assert rec.status == "contained"
    assert any(e["code"] == "DENY_APPROVAL_TIMEOUT" for e in kinds(o, "policy"))


def test_slow_n_of_m_approval_executes_only_after_the_last_vote(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    sa = ScriptedApprover([("alice", "sre-lead", True), ("bob", "dc-ops", True)], delay=2)
    o = run(fleet30, approver=sa, ticks=30)
    (req,) = o.approvals.requests.values()
    assert req.status == "approved" and req.resolved_tick == req.opened_tick + 2
    t_exec = next(t for t, r, _ in o.executed if r == "replace_disk")
    assert t_exec == req.resolved_tick
    assert next(iter(o.records.values())).status == "resolved"
    votes = kinds(o, "approval")
    assert {v["approver"] for v in votes} == {"alice", "bob"}


def test_approval_does_not_bypass_a_denial_that_appears_while_waiting(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    sa = ScriptedApprover([("alice", "sre-lead", True), ("bob", "dc-ops", True)], delay=3)
    o = Orchestrator(fleet30, approver=sa)

    def freeze(orch):
        if orch.fleet.tick == 7:  # a change freeze starts after the request was filed but before it is approved
            orch.policy.cfg.freeze_windows = [{"start": 0, "end": 1000, "allow_tiers": ["REVERSIBLE"], "label": "f"}]

    o.on_tick = freeze
    o.run(25)
    assert "replace_disk" not in [r for _, r, _ in o.executed]
    assert any(e["phase"] == "recheck" and e["code"] == "DENY_FREEZE_WINDOW" for e in kinds(o, "policy"))
    assert next(iter(o.records.values())).denied == [f"replace_disk@{worker}"]


def test_protected_host_reversible_action_needs_the_protected_pool(fleet30):
    prim = first_host(fleet30, "db-primary")
    fleet30.inject(prim, "service_down")
    o = run(fleet30, approver=deny_all, ticks=8)
    assert "restart_service" not in [r for _, r, _ in o.executed]
    assert kinds(o, "approval_request")[0]["code"] == "APPROVAL_PROTECTED_ROLE"
    o2 = run(Fleet(30, seed=2), approver=approve_all, ticks=0)
    o2.fleet.inject(prim, "service_down")
    o2.run(8)
    assert "restart_service" in [r for _, r, _ in o2.executed]


# ---- untrusted planners ---------------------------------------------------------------------------------


def test_sanitise_proposals_drops_non_proposals_and_clamps_ids():
    raw = [Proposal("restart_service", "h001", "ok"), {"runbook": "x"}, None, Proposal(["a"], "h001"),
           Proposal("drain_host", {"nested": "host"}), Proposal("x" * 5000, "h" * 5000, {"nested": 1})]
    out, bad = sanitise_proposals(raw)
    assert bad == 4 and len(out) == 2
    assert len(out[1].runbook) == MAX_ID_LEN and len(out[1].host) == MAX_ID_LEN and out[1].rationale == ""
    assert sanitise_proposals(iter([]))[0] == []
    with pytest.raises(TypeError):
        sanitise_proposals(None)


def test_oversized_plans_are_truncated_and_audited(fleet30, worker):
    class Flood:
        def plan(self, inc, tri):
            return [Proposal("open_ticket", worker, "x")] * 300

    fleet30.inject(worker, "service_down")
    o = run(fleet30, Flood(), ticks=4)
    rec = next(iter(o.records.values()))
    assert rec.truncated == 300 - MAX_PLAN_STEPS
    assert kinds(o, "plan_truncated")[0]["kept"] == MAX_PLAN_STEPS and len(rec.steps) == MAX_PLAN_STEPS


@pytest.mark.parametrize("bad", [None, 7, "restart_service", [None], [{"runbook": "restart_service"}], [object()]])
def test_garbage_from_a_planner_never_crashes_the_loop(fleet30, worker, bad):
    class Bad:
        def plan(self, inc, tri):
            return bad

    fleet30.inject(worker, "service_down")
    o = run(fleet30, Bad(), ticks=6)
    assert o.executed == [] and o.audit.verify()[0]
    assert next(iter(o.records.values())).escalated


def test_planner_exception_escalates_instead_of_propagating(fleet30, worker):
    class Boom:
        def plan(self, inc, tri):
            raise RuntimeError("model fell over")

    fleet30.inject(worker, "service_down")
    o = run(fleet30, Boom(), ticks=5)
    assert any("planner error: RuntimeError" in e["reason"] for e in kinds(o, "escalation"))
    assert o.pages and o.executed == []


def test_structural_denials_are_pruned_at_preflight_but_the_rest_of_the_plan_survives(fleet30, worker):
    fleet30.inject(worker, "service_down")
    o = run(fleet30, Fixed("rm_rf_everything", "restart_service"), ticks=8)
    rec = next(iter(o.records.values()))
    assert [s.status for s in rec.steps] == ["denied", "verified"]
    assert rec.denied == [f"rm_rf_everything@{worker}"] and rec.status == "resolved"
    pre = [e for e in kinds(o, "policy") if e["phase"] == "preflight"]
    assert pre[0]["provisional"] is False and pre[0]["code"] == "DENY_UNKNOWN_RUNBOOK"


def test_transient_denial_waits_and_then_executes(fleet30):
    w1, w2 = [h.id for h in fleet30.hosts.values() if h.role == "worker"][:2]
    cfg = PolicyConfig.from_dict({**PolicyConfig.load("default").to_dict(), "max_actions_per_tick": 1,
                                  "canary": {"enabled": False}})
    fleet30.inject(w1, "service_down")
    fleet30.inject(w2, "service_down")
    o = run(fleet30, policy=Policy(fleet30, cfg), ticks=10)
    got = sorted((t, h) for t, r, h in o.executed if r == "restart_service")
    assert len(got) == 2 and got[0][0] < got[1][0]  # second host waited a tick for the budget
    assert all(r.status == "resolved" for r in o.records.values())
    assert any(e["code"] == "DENY_TICK_BUDGET" for e in kinds(o, "policy"))


# ---- group incidents, summaries, snapshots ---------------------------------------------------------------


def test_rack_wide_failure_is_one_group_incident_with_one_rack_action():
    f = Fleet(30, seed=4)
    rack = sorted(f.topology.racks)[0]
    hosts = f.topology.hosts_in_rack(rack)
    f.inject_rack(rack, "tor_switch_failure")
    o = run(f, approver=approve_all, ticks=15)
    groups = [r for r in o.records.values() if r.is_group]
    assert len(groups) == 1 and groups[0].incident.hypothesis == "tor_switch_failure"
    assert set(groups[0].hosts) == set(hosts)
    assert groups[0].status == "resolved" and groups[0].root_cause.scope == "rack"
    assert [r for _, r, _ in o.executed].count("failover_tor_uplink") == 1
    assert not any(h.faults for h in f.hosts.values())
    assert len(o.records) == 1 + sum(1 for r in o.records.values() if not r.is_group)


def test_late_host_incident_is_merged_into_an_existing_group():
    f = Fleet(30, seed=4)
    rack = sorted(f.topology.racks)[0]
    hosts = list(f.topology.hosts_in_rack(rack))
    for h in hosts[:2]:
        f.inject(h, "uplink_loss")
    o = Orchestrator(f, approver=approve_all)
    o.run(2)  # two standalone host incidents open (below the 3-host grouping threshold)
    assert len(o.records) >= 2 and not any(r.is_group for r in o.records.values())
    for h in hosts[2:6]:
        f.inject(h, "uplink_loss")
    o.run(12)
    merged = [r for r in o.records.values() if r.merged_into]
    assert merged and all(o.records[r.merged_into].is_group for r in merged)
    assert kinds(o, "merged")
    assert all(not r.active for r in merged)


def test_correlation_can_be_switched_off():
    f = Fleet(30, seed=4)
    rack = sorted(f.topology.racks)[0]
    f.inject_rack(rack, "tor_switch_failure")
    o = run(f, approver=approve_all, ticks=6, correlate=False)
    assert not any(r.is_group for r in o.records.values()) and len(o.records) >= 10


def test_summary_snapshot_and_tick_log(fleet30, worker):
    fleet30.inject(worker, "service_down")
    o = run(fleet30, ticks=8)
    s = o.summary()
    assert s["incidents"] == 1 and s["resolved"] == 1 and s["executed"] == 1 and s["audit_ok"] is True
    assert s["mttr_mean"] is not None and s["decisions"]["ALLOW_REVERSIBLE"] >= 1
    assert len(o.tick_log) == 8 and o.tick_log[-1]["tick"] == 8 and o.tick_log[-1]["resolved"] == 1
    snap = o.snapshot()
    assert snap["hosts"] == 30 and snap["pending_approvals"] == 0
    rec = next(iter(o.records.values()))
    d = rec.to_dict()
    assert d["status"] == "resolved" and d["steps"][0]["code"] == "ALLOW_REVERSIBLE" and d["signal"] == "service_down"


def test_on_tick_hook_and_healthy_fleet_is_quiet():
    seen = []
    f = Fleet(30, seed=4)
    o = Orchestrator(f, on_tick=lambda orch: seen.append(orch.fleet.tick))
    o.run(30)
    assert seen == list(range(1, 31)) and not o.records and o.summary()["incidents"] == 0


def test_audit_chain_covers_the_whole_run(fleet30, worker):
    fleet30.inject(worker, "disk_failing")
    o = run(fleet30, approver=approve_all, ticks=25)
    assert o.audit.verify() == (True, None)
    seqs = [e["seq"] for e in o.audit.entries]
    assert seqs == list(range(len(seqs))) and o.audit.entries[0]["kind"] == "run_start"
