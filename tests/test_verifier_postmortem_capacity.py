"""VerifierAgent, PostmortemAgent and CapacityAgent."""
import json

import pytest
from helpers import first_host

from fleetgate import Fleet, Orchestrator
from fleetgate.agents import Proposal
from fleetgate.approvals import AutoApprover
from fleetgate.capacity import CapacityAgent
from fleetgate.llm import FailingLLM, ScriptedLLM
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import PolicyConfig
from fleetgate.postmortem import PostmortemAgent
from fleetgate.runbooks import CATALOG
from fleetgate.verifier import VerifierAgent

# ---- verifier -------------------------------------------------------------------------------------------


def test_due_at_waits_for_the_runbook_duration_plus_settle():
    f = Fleet(10, seed=1)
    v = VerifierAgent(f, settle_ticks=2)
    assert v.due_at(CATALOG["replace_disk"], 5) == 5 + 10 + 2
    assert VerifierAgent(f).due_at(CATALOG["open_ticket"], 5) == 6


def test_verify_ok_and_failed_with_rollback_proposal():
    f = Fleet(10, seed=1)
    f.step()
    ver = VerifierAgent(f)
    f.hosts["h001"].drained = True
    ok = ver.verify("drain_host", "h001")
    assert ok.ok and ok.failed == [] and ok.rollback is None and ok.hosts == ["h001"]
    bad = ver.verify("drain_host", "h002")  # h002 was never drained
    assert not bad.ok and bad.failed == ["h002: state drained != True"]
    assert bad.rollback == Proposal("undrain_host", "h002", "rollback: drain_host failed verification "
                                    "(h002: state drained != True)")
    assert ver.results == [ok, bad] and bad.to_dict()["rollback"]["runbook"] == "undrain_host"


def test_verify_without_rollback_partner_and_over_a_rack():
    f = Fleet(30, seed=1)
    f.step()
    ver = VerifierAgent(f)
    v = ver.verify("restart_service", "h001")
    assert v.ok  # service_up == 1 on a healthy host
    f.inject("h001", "service_down")
    f.step()
    v = ver.verify("restart_service", "h001")
    assert not v.ok and v.rollback is None and "service_up=0" in v.failed[0]
    rack = list(f.topology.hosts_in_rack(f.hosts["h002"].rack))
    for h in rack[:-1]:
        f.hosts[h].drained = True
    rv = ver.verify("migrate_workloads", "h002", rack)
    assert not rv.ok and len(rv.failed) == 1 and rv.rollback.runbook == "restore_rack"


def test_verify_handles_unknown_hosts_and_missing_metrics():
    f = Fleet(10, seed=1)
    ver = VerifierAgent(f)
    assert ver.verify("restart_service", "h001").failed == ["h001: metric service_up unavailable"]  # no sample yet
    assert ver.verify("drain_host", "h001", ["ghost"]).failed == ["ghost: unknown host"]


# ---- postmortem -----------------------------------------------------------------------------------------


def disk_run(approver=approve_all, ticks=30):
    f = Fleet(30, seed=2)
    h = first_host(f, "worker")
    f.inject(h, "disk_failing")
    o = Orchestrator(f, approver=approver)
    o.run(ticks)
    return o, h


def test_postmortem_for_a_resolved_incident():
    o, h = disk_run()
    pa = PostmortemAgent()
    (iid,) = pa.incident_ids(o.audit.entries)
    pm = pa.write(o.audit.entries, iid)
    assert pm.status == "resolved" and pm.hosts == [h] and pm.root_cause == "disk_failing"
    rec = o.records[iid]
    assert pm.mttr_ticks == rec.closed_tick - rec.incident.opened_tick and pm.contained_tick == pm.detected_tick
    assert pm.actions_executed == [f"{r}@{h}" for _, r, _ in o.executed]
    assert pm.actions_denied == [] and pm.rollbacks == [] and pm.pages == 0 and pm.action_items == []
    assert len(pm.approvals) == 1 and pm.approvals[0]["status"] == "approved"
    assert all(v["ok"] for v in pm.verifications) and pm.first_action_tick == pm.detected_tick
    assert "Final status: resolved after" in pm.summary
    md = pm.markdown()
    for needle in ("# Postmortem: disk_failing on h001", "## Timeline", "## Action items", "- none", "MTTR:",
                   "Approvals: 1 requested, 1 approved", "Verifications: 4/4 passed"):
        assert needle in md
    assert pm.to_dict()["incident_id"] == iid and pm.timeline[0]["event"].startswith("detected")


def test_postmortem_action_items_for_a_contained_incident_with_rejected_approval():
    o, h = disk_run(deny_all, 20)
    pm = PostmortemAgent().write(o.audit.entries, next(iter(o.records)))
    assert pm.status == "contained" and pm.mttr_ticks is None
    assert [d["code"] for d in pm.actions_denied] == ["DENY_APPROVAL_REJECTED"]
    text = "\n".join(pm.action_items)
    assert "contained (host drained) but not fixed" in text and "Approval expired or was rejected" in text
    assert "page(s) fired" in text and pm.pages == 1


def test_postmortem_for_an_open_incident_and_approval_timeout():
    o, h = disk_run(AutoApprover("hold"), 8)
    pm = PostmortemAgent().write(o.audit.entries, next(iter(o.records)))
    assert pm.status in ("open", "contained")
    o2, _ = disk_run(AutoApprover("hold"), 40)
    pm2 = PostmortemAgent().write(o2.audit.entries, next(iter(o2.records)))
    assert any("expired" in a or "rejected" in a for a in pm2.action_items) or pm2.approvals[0]["status"] == "expired"
    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "service_down")
    o3 = Orchestrator(f, approver=deny_all, dry_run=True)
    o3.run(8)
    pm3 = PostmortemAgent().write(o3.audit.entries, next(iter(o3.records)))
    assert pm3.status == "open" and "still open" in "\n".join(pm3.action_items)
    assert "(dry-run)" in pm3.markdown()


def test_postmortem_reports_verification_failure_and_rollback():
    class Fan:
        def plan(self, inc, tri):
            return [Proposal("set_fan_profile_max", inc.host, "")]

    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "cooling_failure")
    o = Orchestrator(f, planner=Fan(), approver=approve_all)
    o.run(12)
    iid = next(i for i in o.records if "cooling_failure" in i)
    pm = PostmortemAgent().write(o.audit.entries, iid)
    assert pm.rollbacks and not all(v["ok"] for v in pm.verifications)
    assert any("Verification of set_fan_profile_max failed" in a for a in pm.action_items)
    assert any("FAILED" in e["event"] for e in pm.timeline)
    assert pm.pages >= 1


def test_postmortem_for_a_group_incident_lists_contributing_causes():
    f = Fleet(30, seed=4)
    f.inject_rack(sorted(f.topology.racks)[0], "tor_switch_failure")
    o = Orchestrator(f, approver=approve_all)
    o.run(15)
    gid = next(i for i, r in o.records.items() if r.is_group)
    pm = PostmortemAgent().write(o.audit.entries, gid)
    assert len(pm.hosts) == 10 and pm.root_cause == "tor_switch_failure" and "..." in pm.title
    assert any("symptoms" in a for a in pm.action_items) is bool(pm.contributing)


def test_postmortem_unknown_incident_raises():
    o, _ = disk_run(ticks=5)
    with pytest.raises(KeyError):
        PostmortemAgent().write(o.audit.entries, "inc-nope")


def test_postmortem_llm_writes_only_the_summary_and_falls_back_on_trouble():
    o, _ = disk_run()
    iid = next(iter(o.records))
    base = PostmortemAgent().write(o.audit.entries, iid)
    llm = ScriptedLLM(["The disk failed; the host was drained, replaced, and returned."])
    pm = PostmortemAgent(llm).write(o.audit.entries, iid)
    assert pm.summary.startswith("The disk failed")
    assert pm.timeline == base.timeline and pm.action_items == base.action_items  # everything else is deterministic
    facts = json.loads(llm.calls[0][1])
    assert facts["root_cause"] == "disk_failing" and "timeline" not in facts
    assert PostmortemAgent(FailingLLM()).write(o.audit.entries, iid).summary == base.summary
    assert PostmortemAgent(ScriptedLLM(["word " * 400])).write(o.audit.entries, iid).summary == base.summary
    assert PostmortemAgent(ScriptedLLM([""])).write(o.audit.entries, iid).summary == base.summary


def test_postmortem_works_from_a_reloaded_log(tmp_path):
    from fleetgate.audit import AuditLog

    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "service_down")
    o = Orchestrator(f, audit=AuditLog(tmp_path / "a.jsonl"))
    o.run(8)
    entries = AuditLog.load(tmp_path / "a.jsonl").entries
    pm = PostmortemAgent().write(entries, next(iter(o.records)))
    assert pm.status == "resolved" and pm.actions_executed == [f"restart_service@{pm.hosts[0]}"]


# ---- capacity -------------------------------------------------------------------------------------------


def test_capacity_report_on_a_quiet_fleet():
    f = Fleet(30, seed=2)
    rep = CapacityAgent(f).report([])
    assert rep.cap_hosts == 3 and rep.fleet_drained == 0 and rep.fleet_drain_rate == 0
    assert rep.ticks_until_cap is None
    # the lone validator sits at its capacity floor: no headroom even though nothing is being drained
    assert rep.recommendations == [x for x in rep.recommendations if "floor of 1" in x] and rep.recommendations
    quiet = Fleet(30, seed=2)
    for h in quiet.hosts.values():
        if h.role == "validator":
            h.role = "worker"
    assert CapacityAgent(quiet, PolicyConfig.from_dict({**PolicyConfig.load("default").to_dict(),
                                                        "min_active_per_role": {}})).report([]).recommendations == [
        "no action: drain rate is within headroom for the lead time"]
    assert {r.role for r in rep.roles} == {h.role for h in f.hosts.values()}
    assert "capacity @ tick 0" in rep.text() and rep.to_dict()["cap_hosts"] == 3


def test_capacity_projects_drain_rate_against_the_cap_and_floors():
    f = Fleet(30, seed=2)
    f.tick = 12
    workers = [h.id for h in f.hosts.values() if h.role == "worker"]
    history = [{"tick": 4 + i, "runbook": "drain_host", "host": h, "role": "worker", "dc": "dc1"}
               for i, h in enumerate(workers[:4])]
    for h in workers[:2]:
        f.hosts[h].drained = True
    rep = CapacityAgent(f, window_ticks=24, lead_time_ticks=48).report(history)
    assert rep.fleet_drain_rate == pytest.approx(4 / 12)
    assert rep.ticks_until_cap == pytest.approx(1 / (4 / 12))  # cap 3, 2 drained -> 1 more drain of headroom
    w = next(r for r in rep.roles if r.role == "worker")
    assert w.drained == 2 and w.drain_rate == pytest.approx(4 / 12) and w.recommended_spare >= 1
    assert any(x.startswith("worker: add") and "DC-ops lead time is 48 ticks" in x for x in rep.recommendations)
    assert rep.to_dict()["roles"][0]["role"]
    old = [dict(h, tick=0) for h in history]
    f.tick = 100
    assert CapacityAgent(f, window_ticks=24).report(old).fleet_drain_rate == 0  # outside the window


def test_capacity_flags_over_cap_and_single_points_of_failure():
    f = Fleet(30, seed=2)
    for h in list(f.hosts.values())[:5]:
        h.drained = True
    rep = CapacityAgent(f).report([])
    assert any("over the drain cap (5 > 3)" in r for r in rep.recommendations)
    f2 = Fleet(30, seed=2)
    prims = [h for h in f2.hosts.values() if h.role == "db-primary"]
    for h in prims[1:]:
        h.role = "worker"
    rep2 = CapacityAgent(f2, policy=PolicyConfig.load("default")).report([])
    db = next(r for r in rep2.roles if r.role == "db-primary")
    assert db.recommended_spare >= 1
    assert any(x.startswith("db-primary: 1 active host(s) against a floor of 1") for x in rep2.recommendations)


def test_capacity_notes_faulty_hosts_still_serving():
    f = Fleet(30, seed=2)
    w = first_host(f, "worker")
    f.inject(w, "disk_failing")
    rep = CapacityAgent(f).report([])
    assert any("faulty host(s) still serving" in x for x in rep.recommendations)
