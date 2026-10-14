"""The shipped scenario library: every file validates, covers the simulator, and still behaves as recorded."""
import json

import pytest

from fleetgate.fleet import FAULT_SPECS, GROUP_FAULTS
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.runbooks import CATALOG, Tier
from fleetgate.runner import check_expectations, run_scenario
from fleetgate.scenarios import dumps_scenario, load_scenarios, scenario_dir

SCENARIOS = load_scenarios()
NAMES = sorted(SCENARIOS)
APPROVERS = {"approve_all": approve_all, "deny_all": deny_all}


def test_library_size_and_naming():
    assert len(SCENARIOS) >= 30
    files = sorted(p.stem for p in scenario_dir().glob("*.json"))
    assert files == NAMES  # file name == scenario name, nothing unparsed
    for s in SCENARIOS.values():
        assert s.description and s.tags and s.ticks >= 1


def test_library_covers_the_simulator():
    used = {f for s in SCENARIOS.values() for f in s.faults}
    assert len(used) >= 20, sorted(set(FAULT_SPECS) - used)
    group_events = {e["type"] for s in SCENARIOS.values() for e in s.events}
    assert {"inject_rack", "inject_pdu", "inject_zone", "inject_random"} <= group_events
    modes = {e.get("mode") for s in SCENARIOS.values() for e in s.events}
    assert {"intermittent"} <= modes
    assert {FAULT_SPECS[f].mode for f in used} >= {"step", "ramp", "intermittent"}
    assert any(s.fleet.get("dcs", 1) > 1 for s in SCENARIOS.values())  # multi-datacenter
    assert any(s.fleet.get("load", {}).get("amplitude", 0) > 0 for s in SCENARIOS.values())  # diurnal load
    assert {s.policy for s in SCENARIOS.values()} >= {"default", "strict", "permissive", "freeze", "canary"}
    assert any(not s.events for s in SCENARIOS.values())  # healthy controls


def test_every_group_fault_has_a_scenario():
    kinds = {e.get("fault", {"inject_rack": "tor_switch_failure", "inject_zone": "cooling_failure",
                            "inject_pdu": "pdu_failure"}.get(e["type"])) for s in SCENARIOS.values() for e in s.events}
    assert set(GROUP_FAULTS) <= kinds


def test_files_are_in_canonical_format():
    for p in scenario_dir().glob("*.json"):
        doc = json.loads(p.read_text())
        assert p.read_text() == dumps_scenario(doc), p.name


@pytest.mark.parametrize("who", sorted(APPROVERS))
@pytest.mark.parametrize("name", NAMES)
def test_scenario_matches_its_recorded_expectations(name, who):
    s = SCENARIOS[name]
    r = run_scenario(s, approver=APPROVERS[who])
    summary = r.summary()
    assert check_expectations(summary, s.expect.get(who)) == [], (name, who)
    assert summary["audit_ok"]


@pytest.mark.parametrize("name", NAMES)
def test_safety_holds_in_every_scenario_even_when_everyone_approves(name):
    s = SCENARIOS[name]
    r = run_scenario(s, approver=approve_all)
    o = r.orchestrator
    cap = o.policy.cfg.max_drained_fraction
    assert max((t["drained"] for t in o.tick_log), default=0) / len(r.fleet.hosts) <= cap + 1e-9
    resolved_ids = {e["request_id"] for e in o.audit.entries
                    if e["kind"] == "approval_resolved" and e["status"] == "approved"}
    for e in o.audit.entries:
        if e["kind"] != "executed":
            continue
        assert e["runbook"] in CATALOG and e["runbook"] not in o.policy.cfg.deny_list
        tier = CATALOG[e["runbook"]].tier
        if tier == Tier.DESTRUCTIVE:
            assert e["request_id"] in resolved_ids
    assert o.audit.verify() == (True, None)


@pytest.mark.parametrize("name", NAMES)
def test_dry_run_never_touches_the_fleet(name):
    s = SCENARIOS[name]
    r = run_scenario(s, approver=approve_all, dry_run=True, ticks=min(s.ticks, 25))
    for h in r.fleet.hosts.values():
        assert not (h.drained or h.cordoned or h.throttled or h.ticketed or h.decommissioned)
        assert h.fan_profile == "auto"
    assert all(e["dry_run"] for e in r.orchestrator.audit.entries if e["kind"] == "executed")


def test_healthy_controls_open_no_incidents():
    for name, s in SCENARIOS.items():
        if not s.events:
            r = run_scenario(s)
            assert r.summary()["incidents"] == 0, name


def test_expected_story_for_a_few_headline_scenarios():
    r = run_scenario(SCENARIOS["tor_switch_rack_failure"], approver=approve_all)
    assert sum(rec.is_group for rec in r.orchestrator.records.values()) == 1 and len(r.orchestrator.records) == 1
    assert [rb for _, rb, _ in r.orchestrator.executed] == ["failover_tor_uplink", "open_ticket"]
    r = run_scenario(SCENARIOS["freeze_blocks_disruptive"], approver=approve_all)
    assert r.summary()["faults_contained"] == 1 and "reboot_host" not in [rb for _, rb, _ in r.orchestrator.executed]
    r = run_scenario(SCENARIOS["maintenance_window_reopens"], approver=deny_all)
    assert "reboot_host" in [rb for _, rb, _ in r.orchestrator.executed] and r.summary()["faults_resolved"] == 1
    r = run_scenario(SCENARIOS["ecc_uncorrectable_validator"], approver=approve_all)
    assert r.orchestrator.executed == [] and r.orchestrator.pages  # the lone validator cannot be drained
    r = run_scenario(SCENARIOS["firmware_drift_rollout"], approver=deny_all)
    d = r.orchestrator.policy.decisions
    assert d["ALLOW_CANARY"] >= 1 and d["DENY_CANARY_PENDING"] >= 1  # canary-first made the rest of the campaign wait
