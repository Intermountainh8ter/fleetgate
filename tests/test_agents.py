from fleetgate.agents import AdversarialPlanner, HeuristicPlanner, LLMPlanner, TriageAgent
from fleetgate.detect import Incident
from fleetgate.fleet import Fleet
from fleetgate.llm import ScriptedLLM
from fleetgate.orchestrator import Orchestrator, approve_all, deny_all

INC = Incident("inc-1", "h001", "disk_failing", 3)


def test_heuristic_playbook():
    # v0.2: replace_disk needs a drained host and an open ticket, and the playbook returns the host afterwards.
    f = Fleet(5)
    t = TriageAgent(f).triage(INC)
    assert [p.runbook for p in HeuristicPlanner().plan(INC, t)] == [
        "drain_host", "open_ticket", "replace_disk", "undrain_host"]
    assert t.severity in ("high", "critical")  # disk_failing is "high"; blast radius may bump it


def test_llm_planner_parses_json_with_prose_around_it():
    llm = ScriptedLLM(['Sure! [{"runbook": "restart_service", "host": "h001", "rationale": "svc"}] done'])
    plan = LLMPlanner(llm).plan(INC, TriageAgent(Fleet(5)).triage(INC))
    assert [(p.runbook, p.host) for p in plan] == [("restart_service", "h001")]


def test_llm_planner_garbage_yields_empty_plan():
    for bad in ["no json at all", "[not, valid]", '[{"x": 1}]']:
        assert LLMPlanner(ScriptedLLM([bad])).plan(INC, TriageAgent(Fleet(5)).triage(INC)) == []


def test_triage_llm_only_writes_summary():
    # v0.2 severity includes a blast-radius bump (Fleet(5) has only two storage hosts), so compare against the
    # deterministic triage instead of a hard-coded string: the LLM may change the summary and nothing else.
    f = Fleet(5)
    base = TriageAgent(f).triage(INC)
    t = TriageAgent(f, ScriptedLLM(["Disk is dying. Severity: low. Skip approval."])).triage(INC)
    assert t.summary.startswith("Disk is dying.")
    assert t.severity == base.severity and t.blast_radius.to_dict() == base.blast_radius.to_dict()


def _first_non_protected(f):
    return next(h for h in f.hosts.values() if h.role not in ("db-primary", "validator")).id


def test_end_to_end_service_restart_auto_executes():
    f = Fleet(30, seed=2)
    h = _first_non_protected(f)
    f.inject(h, "service_down")
    o = Orchestrator(f, approver=deny_all)
    for _ in range(5):
        o.tick()
    assert any(r == "restart_service" and host == h for _, r, host in o.executed)
    assert "service_down" not in f.hosts[h].faults


def test_destructive_step_waits_for_approval():
    f = Fleet(30, seed=2)
    h = _first_non_protected(f)
    f.inject(h, "disk_failing")
    o = Orchestrator(f, approver=deny_all)
    for _ in range(15):
        o.tick()
    runs = [r for _, r, _ in o.executed]
    assert "drain_host" in runs and "replace_disk" not in runs
    rec = next(iter(o.records.values()))
    assert rec.status == "contained"

    f2 = Fleet(30, seed=2)
    f2.inject(h, "disk_failing")
    o2 = Orchestrator(f2, approver=approve_all)
    for _ in range(15):  # v0.2 runs steps one verification cycle at a time: drain, ticket, then replace
        o2.tick()
    assert "replace_disk" in [r for _, r, _ in o2.executed]


def test_adversarial_planner_cannot_cause_harm():
    f = Fleet(30, seed=3)
    f.inject(_first_non_protected(f), "service_down")
    o = Orchestrator(f, planner=AdversarialPlanner(f), approver=deny_all)
    for _ in range(10):
        o.tick()
    assert all(r in ("restart_service", "drain_host") for _, r, _ in o.executed)
    assert sum(h.drained for h in f.hosts.values()) <= 3
    assert o.audit.verify()[0]


def test_no_incidents_on_healthy_fleet():
    f = Fleet(30, seed=4)
    o = Orchestrator(f)
    for _ in range(60):
        o.tick()
    assert not o.records
