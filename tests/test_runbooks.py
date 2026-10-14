import copy
import json

import pytest

from fleetgate.fleet import FAULT_SPECS, Fleet
from fleetgate.runbooks import CATALOG, DEFAULT_SPEC, GROUP_PLAYBOOK, PLAYBOOK, REGISTRY, Risk, RunbookRegistry, Tier
from fleetgate.schema import SchemaError

SPEC = json.loads(DEFAULT_SPEC.read_text())


def test_catalogue_size_tiers_and_pairs():
    assert len(CATALOG) >= 25
    for tier in Tier:
        assert REGISTRY.by_tier(tier), tier
    assert Risk is Tier and CATALOG["replace_disk"].risk == Tier.DESTRUCTIVE
    pairs = dict(REGISTRY.rollback_pairs())
    assert pairs["drain_host"] == "undrain_host" and pairs["migrate_workloads"] == "restore_rack"
    assert len(pairs) >= 6


def test_every_fault_has_a_playbook_and_all_steps_exist():
    assert set(PLAYBOOK) == set(FAULT_SPECS)
    for steps in list(PLAYBOOK.values()) + list(GROUP_PLAYBOOK.values()):
        assert all(s in CATALOG for s in steps)


def test_rollback_is_never_riskier_than_the_action():
    for rb in CATALOG.values():
        if rb.rollback:
            assert CATALOG[rb.rollback].tier <= rb.tier


def test_destructive_runbooks_require_drain_or_ticket_preconditions():
    for rb in REGISTRY.by_tier(Tier.DESTRUCTIVE):
        assert rb.preconditions, rb.id


def test_roundtrip_to_dict_and_load(tmp_path):
    again = RunbookRegistry.from_dict(REGISTRY.to_dict())
    assert again.runbooks.keys() == CATALOG.keys() and again.playbooks == PLAYBOOK
    p = tmp_path / "rb.json"
    p.write_text(json.dumps(REGISTRY.to_dict()))
    assert RunbookRegistry.load(p).source == str(p)
    assert CATALOG["drain_host"].to_dict()["tier"] == "REVERSIBLE"


def _mutate(fn):
    spec = copy.deepcopy(SPEC)
    fn(spec)
    return spec


@pytest.mark.parametrize("fn,needle", [
    (lambda s: s["runbooks"][0].update(id="Bad Id"), "does not match"),
    (lambda s: s["runbooks"][0].update(tier="NUCLEAR"), "not one of"),
    (lambda s: s["runbooks"][1].update(id=s["runbooks"][0]["id"]), "duplicate runbook id"),
    (lambda s: s["runbooks"][0].update(preconditions=["moon_in_taurus"]), "unknown precondition"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "clear_fault", "fault": "gremlins"}]), "known fault"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "clear_faults", "faults": ["thermal", "nope"]}]),
     "unknown faults"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "set_state", "field": "drained", "value": "yes"}]), "boolean"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "set_state", "field": "fan_profile", "value": "turbo"}]),
     "auto|max"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "set_state", "field": "role", "value": 3}]), "string"),
    (lambda s: s["runbooks"][0].update(effects=[{"op": "set_state", "field": "drained"}]), "needs field and value"),
    (lambda s: s["runbooks"][0].update(verify=[{"metric": "temp_c", "state": "drained", "op": ">", "value": 1,
                                                "equals": True}]), "exactly one"),
    (lambda s: s["runbooks"][0].update(verify=[{"metric": "temp_c"}]), "needs op and value"),
    (lambda s: s["runbooks"][0].update(verify=[{"state": "drained"}]), "needs equals"),
    (lambda s: s["runbooks"][0].update(rollback="ghost"), "not a runbook"),
    (lambda s: s["playbooks"].update(unicorn=["drain_host"]), "unknown fault"),
    (lambda s: s["playbooks"].update(thermal=["ghost"]), "unknown runbook"),
    (lambda s: s["group_playbooks"].update(x=["ghost"]), "unknown runbook"),
    (lambda s: s.update(extra=1), "unexpected property"),
])
def test_invalid_specs_are_rejected_at_load(fn, needle):
    with pytest.raises(SchemaError) as ei:
        RunbookRegistry.from_dict(_mutate(fn))
    assert needle in str(ei.value)


def test_rollback_riskier_than_action_is_rejected():
    def f(s):
        for r in s["runbooks"]:
            if r["id"] == "drain_host":
                r["rollback"] = "replace_disk"
    with pytest.raises(SchemaError, match="riskier"):
        RunbookRegistry.from_dict(_mutate(f))


def test_preconditions_probe_real_state():
    f = Fleet(10, seed=1)
    drain, undrain = CATALOG["drain_host"], CATALOG["undrain_host"]
    assert drain.failed_preconditions(f, "h001") == [] and undrain.failed_preconditions(f, "h001") == ["host_drained"]
    f.hosts["h001"].drained = True
    assert drain.failed_preconditions(f, "h001") == ["host_not_drained"]
    assert CATALOG["replace_disk"].failed_preconditions(f, "h001") == ["ticket_open"]
    assert drain.failed_preconditions(f, "nope") == ["host_known"]
    f.inject("h002", "bmc_unreachable")
    assert "bmc_reachable" in CATALOG["set_fan_profile_max"].failed_preconditions(f, "h002")
    f.hosts["h003"].decommissioned = True
    assert "host_not_decommissioned" in CATALOG["open_ticket"].failed_preconditions(f, "h003")
    role = f.hosts["h004"].role
    assert CATALOG["failover_db_primary"].failed_preconditions(f, "h004") == (
        [] if role == "db-primary" else ["role:db-primary"])


def test_apply_changes_state_and_schedules_fault_clears():
    f = Fleet(10, seed=1)
    f.inject("h001", "service_down")
    res = CATALOG["restart_service"].apply(f, "h001")
    assert res.hosts == ["h001"] and any("clearing in 1 ticks" in c for c in res.changes)
    assert "service_down" in f.hosts["h001"].faults  # the fix lands after duration_ticks
    f.step()
    f.step()
    assert "service_down" not in f.hosts["h001"].faults
    res = CATALOG["drain_host"].apply(f, "h002")
    assert f.hosts["h002"].drained and res.changes == ["h002.drained: False -> True"]
    assert CATALOG["drain_host"].apply(f, "h002").changes == []  # idempotent


def test_dry_run_changes_nothing_but_reports_it():
    f = Fleet(10, seed=1)
    f.inject("h001", "service_down")
    before = (dict(f.hosts["h001"].faults), f.hosts["h001"].drained, list(f.pending))
    res = CATALOG["drain_host"].apply(f, "h001", dry_run=True)
    res2 = CATALOG["restart_service"].apply(f, "h001", dry_run=True)
    assert res.dry_run and res.changes == ["h001.drained: False -> True"] and res2.changes
    assert (dict(f.hosts["h001"].faults), f.hosts["h001"].drained, list(f.pending)) == before


def test_rack_scope_runbook_touches_the_whole_rack():
    f = Fleet(30, seed=1)
    rack = f.hosts["h001"].rack
    res = CATALOG["migrate_workloads"].apply(f, "h001")
    assert set(res.hosts) == set(f.topology.hosts_in_rack(rack)) and len(res.hosts) == 10
    assert all(f.hosts[h].drained for h in res.hosts)
    CATALOG["restore_rack"].apply(f, "h001")
    assert not any(f.hosts[h].drained for h in res.hosts)


def test_clear_all_faults_effect_and_properties():
    f = Fleet(10, seed=1)
    f.hosts["h001"].drained = True
    f.hosts["h001"].ticketed = True
    f.inject("h001", "disk_failing")
    f.inject("h001", "ecc_correctable")
    dec = CATALOG["decommission_host"]
    assert dec.failed_preconditions(f, "h001") == []
    dec.apply(f, "h001")
    f.step()
    f.step()
    assert not f.hosts["h001"].faults and f.hosts["h001"].decommissioned
    assert dec.cleared_faults == tuple(FAULT_SPECS)
    assert CATALOG["drain_host"].drains and not CATALOG["restart_service"].drains
    assert CATALOG["replace_disk"].cleared_faults == ("disk_failing", "disk_latency", "nvme_wear")


def test_verify_probes_state_and_metric():
    f = Fleet(10, seed=1)
    f.step()
    m = f.last_sample["h001"]
    drain = CATALOG["drain_host"]
    assert drain.verify_probes(f, "h001", m) == ["state drained != True"]
    f.hosts["h001"].drained = True
    assert drain.verify_probes(f, "h001", m) == []
    restart = CATALOG["restart_service"]
    assert restart.verify_probes(f, "h001", m) == []
    assert restart.verify_probes(f, "h001", {"service_up": 0.0})[0].startswith("service_up=0 not >=")
    assert restart.verify_probes(f, "h001", None) == ["metric service_up unavailable"]
