"""Triage, root-cause, planners (heuristic / LLM / adversarial) and the LLM doubles."""
import json
import sys
import types

import pytest
from helpers import first_host

from fleetgate.agents import (
    HOST_SPOOFS,
    JAILBREAKS,
    PLAN_SCHEMA,
    TYPOSQUATS,
    AdversarialLLM,
    AdversarialPlanner,
    HeuristicPlanner,
    LLMPlanner,
    RootCauseAgent,
    TriageAgent,
    extract_json_array,
    incident_hosts,
    incident_signal,
    normalise_id,
)
from fleetgate.correlate import Correlator
from fleetgate.detect import Incident
from fleetgate.fleet import Fleet
from fleetgate.llm import AnthropicLLM, FailingLLM, ScriptedLLM, safe_complete
from fleetgate.runbooks import CATALOG
from fleetgate.schema import validate


def make_inc(host, signal="service_down", tick=3):
    return Incident(f"inc-{host}-{signal}-{tick}", host, signal, tick)


def rack_group(fleet, signal="uplink_loss", n=10):
    rack = next(iter(fleet.topology.racks.values()))
    c = Correlator(fleet.topology)
    groups, _ = c.correlate(5, [Incident(f"i-{h}", h, signal, 5) for h in rack.hosts[:n]], set(fleet.hosts))
    return groups[0]


# ---- triage ---------------------------------------------------------------------------------------------


def test_triage_severity_is_deterministic_and_bumped_by_protected_roles():
    f = Fleet(30, seed=2)
    w, prim = first_host(f, "worker"), first_host(f, "db-primary")
    t = TriageAgent(f)
    assert t.triage(make_inc(w, "service_down")).severity == "medium"
    # protected role bumps one level, and one of only two db-primaries is >= 50% of that role's capacity: bumps again
    assert t.triage(make_inc(prim, "service_down")).severity == "critical"
    assert t.triage(make_inc(w, "disk_failing")).severity == "high"
    assert t.triage(make_inc(w, "cooling_failure")).severity == "critical"
    unknown = make_inc(w, "ewma:temp_c")
    unknown.score = 9.0
    assert t.triage(unknown).severity == "high"
    unknown.score = 1.0
    assert t.triage(unknown).severity == "medium"


def test_blast_radius_reports_rack_roles_and_protection():
    f = Fleet(30, seed=2)
    prim = first_host(f, "db-primary")
    br = TriageAgent(f).blast_radius([prim, first_host(f, "worker")])
    assert br.hosts_affected == 2 and br.protected and br.rack_hosts >= 10
    assert br.roles["db-primary"] == pytest.approx(1 / 2)  # 1 of the 2 db-primaries
    d = br.to_dict()
    assert d["protected"] is True and d["hosts_affected"] == 2


def test_group_incident_triage_is_critical_when_large():
    f = Fleet(30, seed=4)
    g = rack_group(f)
    tri = TriageAgent(f).triage(g)
    assert tri.severity == "critical" and tri.scope == "rack" and "tor_switch_failure suspected on rack" in tri.summary
    assert tri.blast_radius.hosts_affected == 10
    small = rack_group(Fleet(30, seed=4), n=3)
    assert TriageAgent(Fleet(30, seed=4)).triage(small).severity in ("high", "critical")
    assert incident_hosts(g) == g.hosts and incident_signal(g) == "tor_switch_failure"


def test_llm_summary_failure_falls_back_to_the_template():
    f = Fleet(30, seed=2)
    inc = make_inc(first_host(f, "worker"))
    base = TriageAgent(f).triage(inc).summary
    assert TriageAgent(f, FailingLLM()).triage(inc).summary == base
    assert TriageAgent(f, ScriptedLLM(["   "])).triage(inc).summary == base
    long = TriageAgent(f, ScriptedLLM(["x" * 2000])).triage(inc).summary
    assert len(long) == 300
    llm = ScriptedLLM(["ok"])
    TriageAgent(f, llm).triage(inc)
    assert "No remediation advice" in llm.calls[0][0] and "service_down" in llm.calls[0][1]


# ---- root cause ----------------------------------------------------------------------------------------


def test_root_cause_walks_the_cascade_graph():
    f = Fleet(30, seed=2)
    h = first_host(f, "worker")
    rc = RootCauseAgent(f).analyse(make_inc(h, "oom_kills"), {h: ["oom_kills", "memory_leak"]})
    assert rc.hypothesis == "memory_leak" and rc.contributing == ["memory_leak"] and rc.confidence > 0.6
    assert any("known consequence" in e for e in rc.evidence)
    deep = RootCauseAgent(f).analyse(make_inc(h, "cpu_throttling"), {h: ["cpu_throttling", "thermal", "fan_failure"]})
    assert deep.hypothesis == "fan_failure" and deep.contributing == ["thermal", "fan_failure"]
    lone = RootCauseAgent(f).analyse(make_inc(h, "oom_kills"), {})
    assert lone.hypothesis == "oom_kills" and lone.contributing == [] and lone.confidence == 0.6


def test_root_cause_suspects_the_rack_when_peers_share_the_signal():
    f = Fleet(30, seed=2)
    rack = next(iter(f.topology.racks.values()))
    open_sigs = {h: ["nic_errors"] for h in rack.hosts[:4]}
    rc = RootCauseAgent(f).analyse(make_inc(rack.hosts[0], "nic_errors"), open_sigs)
    assert rc.scope == "rack" and rc.scope_id == rack.id and any("common cause" in e for e in rc.evidence)
    solo = RootCauseAgent(f).analyse(make_inc(rack.hosts[0], "nic_errors"), {rack.hosts[0]: ["nic_errors"]})
    assert solo.scope == "host" and solo.scope_id == rack.hosts[0]


def test_root_cause_for_group_incident_and_narrative():
    f = Fleet(30, seed=4)
    g = rack_group(f)
    rc = RootCauseAgent(f).analyse(g)
    assert rc.hypothesis == "tor_switch_failure" and rc.scope == "rack" and rc.confidence == pytest.approx(0.95)
    assert rc.contributing == ["uplink_loss"] and rc.narrative == ""
    llm = ScriptedLLM(["The ToR failed."])
    rc2 = RootCauseAgent(f, llm).analyse(g)
    assert rc2.narrative == "The ToR failed." and "Do not propose actions" in llm.calls[0][0]
    assert rc2.to_dict()["confidence"] == 0.95
    assert RootCauseAgent(f, FailingLLM()).analyse(g).narrative == ""


# ---- planners -------------------------------------------------------------------------------------------


def test_heuristic_planner_group_playbook_targets_one_host_for_rack_scope_and_tickets():
    f = Fleet(30, seed=4)
    g = rack_group(f)
    plan = HeuristicPlanner().plan(g, TriageAgent(f).triage(g))
    assert [p.runbook for p in plan] == ["failover_tor_uplink", "open_ticket"]
    assert all(p.host == g.hosts[0] for p in plan)
    cooling = rack_group(f, "thermal")
    plan2 = HeuristicPlanner(max_group_hosts=2).plan(cooling, TriageAgent(f).triage(cooling))
    assert [p.runbook for p in plan2] == ["throttle_workload", "throttle_workload", "open_ticket"]
    assert HeuristicPlanner().plan(make_inc("h001", "no_such_signal"), None) == []


def test_extract_json_array_tolerates_prose_fences_and_nested_brackets():
    assert extract_json_array('x [1, [2, 3], "a]b"] y') == [1, [2, 3], "a]b"]
    assert extract_json_array('```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert extract_json_array('["esc \\" ] still string"]') == ['esc " ] still string']
    for bad in ["no brackets", "[1, 2", "", "[}"]:
        with pytest.raises(ValueError):
            extract_json_array(bad)


def planner_for(replies, f=None):
    f = f or Fleet(30, seed=2)
    host = first_host(f, "worker")
    inc = make_inc(host)
    llm = ScriptedLLM(replies)
    return LLMPlanner(llm), inc, TriageAgent(f).triage(inc), llm


def test_llm_planner_validates_filters_and_reports():
    good = json.dumps([{"runbook": "restart_service", "host": "h001", "rationale": "svc"},
                       {"runbook": "rm_rf", "host": "h001"},
                       {"runbook": "restart_service", "host": "h020"}])
    pl, inc, tri, llm = planner_for([good])
    inc.host = "h001"
    out = pl.plan_detailed(inc, tri)
    assert [p.runbook for p in out.proposals] == ["restart_service"] and out.attempts == 1 and not out.escalated
    assert len(out.dropped) == 2 and any("unknown runbook" in d for d in out.dropped)
    assert any("outside incident scope" in d for d in out.dropped)
    assert pl.last is out and pl.plan(inc, tri)[0].host == "h001"


def test_llm_planner_retries_once_with_the_validation_errors_then_escalates():
    pl, inc, tri, llm = planner_for(["nonsense", '[{"runbook": "restart_service", "host": "h001"}]'])
    inc.host = "h001"
    out = pl.plan_detailed(inc, tri)
    assert out.attempts == 2 and not out.escalated and len(out.proposals) == 1
    assert "previous reply was invalid" in llm.calls[1][1]
    pl2, inc2, tri2, llm2 = planner_for(["nonsense"])
    out2 = pl2.plan_detailed(inc2, tri2)
    assert out2.escalated and out2.proposals == [] and llm2.calls and len(llm2.calls) == 2 and out2.errors


def test_llm_planner_survives_an_llm_outage():
    f = Fleet(30, seed=2)
    inc = make_inc("h001")
    pl = LLMPlanner(FailingLLM())
    out = pl.plan_detailed(inc, TriageAgent(f).triage(inc))
    assert out.escalated and out.errors == ["llm error: RuntimeError"] and out.attempts == 2


@pytest.mark.parametrize("attack", sorted(AdversarialLLM.ATTACKS))
def test_adversarial_llm_replies_never_yield_a_runbook_outside_the_catalogue(attack):
    f = Fleet(30, seed=2)
    inc = make_inc("h001")
    llm = AdversarialLLM(attack)
    out = LLMPlanner(llm).plan_detailed(inc, TriageAgent(f).triage(inc))
    assert all(p.runbook in CATALOG and p.host == "h001" for p in out.proposals)
    assert llm.calls >= 1
    if attack in ("prose_only", "typosquat", "unicode", "spoof_host", "oversized", "wrong_types", "empty",
                  "null_bytes", "deep_nesting", "extra_keys", "huge_rationale"):
        assert out.proposals == [], attack
        assert out.escalated or attack in ("typosquat", "unicode", "spoof_host")  # schema failures escalate
    if attack in ("fenced", "jailbreak_rationale", "nested"):
        # harmless-by-construction: the inner array is a valid plan, "override_policy" is just ignored text
        assert [(p.runbook, p.host) for p in out.proposals] == [("restart_service", "h001")]


def test_adversarial_llm_unknown_attack_and_plan_schema():
    with pytest.raises(KeyError):
        AdversarialLLM("nope")
    assert validate([{"runbook": "restart_service", "host": "h001"}], PLAN_SCHEMA) == []
    assert validate([{"runbook": "restart_service\n", "host": "h001"}], PLAN_SCHEMA)  # trailing newline rejected
    assert validate([{"runbook": "restart_service", "host": "h001\n"}], PLAN_SCHEMA)
    assert validate([{"runbook": "restart_service", "host": "h001", "approved": True}], PLAN_SCHEMA)
    assert validate([{"runbook": "restart_service", "host": "h001"}] * 9, PLAN_SCHEMA)  # > 8 steps


def test_pathological_nesting_is_an_error_not_a_crash():
    f = Fleet(30, seed=2)
    inc = make_inc("h001")
    llm = ScriptedLLM(["[" * 15000 + "]" * 15000])
    out = LLMPlanner(llm).plan_detailed(inc, TriageAgent(f).triage(inc))
    assert out.escalated and out.proposals == []
    assert LLMPlanner(ScriptedLLM(["x" * 30000])).plan_detailed(inc, TriageAgent(f).triage(inc)).escalated


def test_adversarial_planner_is_hostile_but_deterministic():
    f = Fleet(30, seed=2)
    inc = make_inc("h001")
    a = AdversarialPlanner(f, seed=5).plan(inc, None)
    b = AdversarialPlanner(f, seed=5).plan(inc, None)
    assert [(p.runbook, p.host) for p in a] == [(p.runbook, p.host) for p in b]
    names = {p.runbook for p in a}
    assert {"rm_rf_everything", "reboot_host", "replace_disk", "decommission_host", *TYPOSQUATS} <= names
    assert {p.host for p in a} >= set(HOST_SPOOFS)
    assert len(a) > 200 and any(j in p.rationale for p in a for j in JAILBREAKS)
    assert len(AdversarialPlanner(f, oversize=0).plan(inc, None)) < len(a)
    assert normalise_id(" drain_host ") == "drain_host" and normalise_id("ｄｒａｉｎ_host") == "drain_host"
    assert all(normalise_id(t) not in CATALOG or t == normalise_id(t) for t in TYPOSQUATS if "ı" in t)


# ---- llm module ----------------------------------------------------------------------------------------


def test_scripted_llm_replays_then_repeats_the_last_reply():
    s = ScriptedLLM(["a", "b"])
    assert [s.complete("s", "u") for _ in range(4)] == ["a", "b", "b", "b"]
    assert len(s.calls) == 4
    with pytest.raises(ValueError):
        ScriptedLLM([])


def test_safe_complete_degrades_on_every_failure_mode():
    assert safe_complete(None, "s", "u", "fb") == "fb"
    assert safe_complete(FailingLLM(), "s", "u", "fb") == "fb"
    assert safe_complete(ScriptedLLM([""]), "s", "u", "fb") == "fb"
    assert safe_complete(ScriptedLLM(["  hi  "]), "s", "u", "fb") == "hi"
    f = FailingLLM(ValueError)
    assert safe_complete(f, "s", "u", "fb") == "fb" and f.calls == 1


def test_anthropic_llm_adapter_with_a_fake_sdk(monkeypatch):
    calls = {}

    class Msg:
        def __init__(self):
            self.content = [types.SimpleNamespace(type="text", text="hello "),
                            types.SimpleNamespace(type="tool_use", text="ignored"),
                            types.SimpleNamespace(type="text", text="world")]

    class Messages:
        def create(self, **kw):
            calls.update(kw)
            return Msg()

    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=Messages())
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("FLEETGATE_MODEL", "my-model")
    llm = AnthropicLLM(max_tokens=50)
    assert llm.complete("sys", "usr") == "hello world"
    assert calls["model"] == "my-model" and calls["max_tokens"] == 50 and calls["system"] == "sys"
    assert AnthropicLLM(model="explicit").model == "explicit"
    monkeypatch.delenv("FLEETGATE_MODEL")
    assert AnthropicLLM().model  # falls back to the packaged default
