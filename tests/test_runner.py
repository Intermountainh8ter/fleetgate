"""run_scenario / score: end-to-end runs scored against simulator ground truth."""
import copy

import pytest

from fleetgate.agents import AdversarialPlanner
from fleetgate.audit import AuditLog
from fleetgate.llm import ScriptedLLM
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import PolicyConfig
from fleetgate.runner import FaultOutcome, check_expectations, run_scenario
from fleetgate.scenarios import Scenario

SVC = Scenario.from_dict({
    "name": "svc", "fleet": {"hosts": 30, "seed": 5}, "ticks": 20,
    "events": [{"tick": 2, "type": "inject", "host": {"role": "worker", "nth": 0}, "fault": "service_down"}]})
DISK = Scenario.from_dict({
    "name": "disk", "fleet": {"hosts": 30, "seed": 5}, "ticks": 30,
    "events": [{"tick": 2, "type": "inject", "host": {"role": "worker", "nth": 0}, "fault": "disk_failing"}]})
RACK = Scenario.from_dict({
    "name": "rack", "fleet": {"hosts": 40, "seed": 3}, "ticks": 20,
    "events": [{"tick": 4, "type": "inject_rack", "rack": {"index": 0}}]})


def test_single_fault_run_is_scored_detected_and_resolved():
    r = run_scenario(SVC)
    (o,) = r.outcomes
    assert isinstance(o, FaultOutcome) and o.fault == "service_down" and o.injected_tick == 2
    assert o.detected_tick == 4 and o.ttd == 2 and o.exact_signal and o.status == "resolved"
    assert o.ttr is not None and o.ttr > o.ttd
    s = r.summary()
    assert s["scenario"] == "svc" and s["policy"] == "default" and s["faults_injected"] == 1
    assert s["faults_detected"] == 1 and s["faults_resolved"] == 1 and s["ttd_mean"] == 2.0
    assert s["spurious_incidents"] == 0 and s["audit_ok"] is True
    assert r.fleet is r.orchestrator.fleet and r.events[0]["type"] == "inject" and r.events[0]["tick"] == 2
    assert o.to_dict()["ttd"] == 2


def test_scenario_events_are_audited():
    r = run_scenario(SVC)
    evs = [e for e in r.orchestrator.audit.entries if e["kind"] == "scenario_event"]
    assert len(evs) == 1 and evs[0]["fault"] == "service_down" and evs[0]["tick"] == 2


def test_ticks_override_and_seed_offset_change_the_run():
    short = run_scenario(SVC, ticks=3)
    assert short.orchestrator.fleet.tick == 3 and short.outcomes[0].status == "undetected"  # detected at tick 4
    a = run_scenario(SVC, seed_offset=0).orchestrator.audit.head
    b = run_scenario(SVC, seed_offset=1).orchestrator.audit.head
    assert a != b and run_scenario(SVC).orchestrator.audit.head == a  # deterministic per seed


def test_policy_and_approver_change_the_outcome_but_not_detection():
    approved = run_scenario(DISK, approver=approve_all).summary()
    denied = run_scenario(DISK, approver=deny_all).summary()
    assert approved["faults_resolved"] == 1 and denied["faults_resolved"] == 0 and denied["faults_contained"] == 1
    assert approved["faults_detected"] == denied["faults_detected"] == 1
    strict = run_scenario(DISK, policy="strict", approver=approve_all)
    assert strict.policy == "strict" and strict.orchestrator.policy.cfg.max_actions_per_tick == 1
    custom = PolicyConfig.load("permissive")
    assert run_scenario(DISK, policy=custom, approver=approve_all).policy == "permissive"


def test_dry_run_leaves_the_fault_in_place():
    r = run_scenario(SVC, dry_run=True)
    assert r.outcomes[0].status == "open" and r.summary()["dry_run"] is True and r.orchestrator.executed


def test_rack_fault_is_scored_per_host_but_handled_as_one_group_incident():
    r = run_scenario(RACK, approver=approve_all)
    assert len(r.outcomes) == 10 and all(o.group for o in r.outcomes)
    assert all(o.detected_tick is not None and o.status == "resolved" for o in r.outcomes)
    assert len({o.incident_id for o in r.outcomes}) == 1
    assert sum(rec.is_group for rec in r.orchestrator.records.values()) == 1
    assert r.summary()["faults_injected"] == 10


def test_correlation_off_means_one_incident_per_host():
    r = run_scenario(RACK, approver=approve_all, correlate=False)
    assert len({o.incident_id for o in r.outcomes}) == 10


def test_an_undetectable_fault_is_reported_undetected_and_a_cleared_one_resolved():
    quiet = Scenario.from_dict({
        "name": "q", "fleet": {"hosts": 20, "seed": 5}, "ticks": 12,
        "events": [{"tick": 1, "type": "inject", "host": "h001", "fault": "firmware_mismatch"},
                   {"tick": 2, "type": "clear", "host": "h001", "fault": "firmware_mismatch"}]})
    r = run_scenario(quiet)
    assert r.outcomes[0].status == "resolved" and r.outcomes[0].detected_tick is None
    never = Scenario.from_dict({
        "name": "n", "fleet": {"hosts": 20, "seed": 5}, "ticks": 3,
        "events": [{"tick": 2, "type": "inject", "host": "h001", "fault": "service_down"}]})
    o = run_scenario(never).outcomes[0]
    assert o.status == "undetected" and o.ttd is None and o.ttr is None


def test_custom_audit_planner_and_llm_are_plumbed_through(tmp_path):
    audit = AuditLog(tmp_path / "run.jsonl")
    r = run_scenario(SVC, audit=audit, planner=AdversarialPlanner(SVC.build_fleet(), 0), approver=deny_all)
    assert (tmp_path / "run.jsonl").exists() and r.orchestrator.audit is audit
    assert all(rb in ("restart_service", "drain_host", "open_ticket") for _, rb, _ in r.orchestrator.executed)
    llm = ScriptedLLM(["one-line summary"])
    r2 = run_scenario(SVC, llm=llm)
    assert llm.calls and r2.orchestrator.audit.of_kind("triage")[0]["summary"] == "one-line summary"


def test_unknown_scenario_policy_name_raises():
    s = copy.deepcopy(SVC)
    s.policy = "nope"
    with pytest.raises(FileNotFoundError):
        run_scenario(s)


def test_check_expectations_reports_every_violated_bound():
    summary = run_scenario(DISK, approver=approve_all).summary()
    ok = {"min": {"faults_detected": 1, "faults_resolved": 1}, "max": {"spurious_incidents": 0, "pages": 0}}
    assert check_expectations(summary, ok) == []
    bad = {"min": {"faults_resolved": 2, "no_such_key": 1}, "max": {"executed": 1}}
    msgs = check_expectations(summary, bad)
    assert len(msgs) == 3 and "faults_resolved: expected >= 2, got 1" in msgs[0]
    assert any("no_such_key" in m for m in msgs) and any("executed: expected <= 1" in m for m in msgs)
    assert check_expectations(summary, None) == []
    assert check_expectations({**summary, "audit_ok": False}, None) == ["audit chain failed verification"]


def test_follow_on_incidents_are_not_counted_as_false_positives():
    fan = Scenario.from_dict({"name": "fan", "fleet": {"hosts": 30, "seed": 5}, "ticks": 30,
                              "events": [{"tick": 2, "type": "inject", "host": {"role": "worker", "nth": 0},
                                          "fault": "fan_failure"}]})
    s = run_scenario(fan, approver=approve_all).summary()
    assert s["follow_on_incidents"] >= 1 and s["spurious_incidents"] == 0  # thermal is a real consequence
    quiet = Scenario.from_dict({"name": "q", "fleet": {"hosts": 30, "seed": 5}, "ticks": 5, "events": []})
    # an incident with no fault in the ground truth would be a false positive
    r = run_scenario(quiet)
    r.fleet.inject("h001", "service_down")
    r.orchestrator.run(4)
    r.fleet.fault_log.clear()
    assert r.summary()["spurious_incidents"] == 1
