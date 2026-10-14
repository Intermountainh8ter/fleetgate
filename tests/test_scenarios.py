"""Scenario DSL: schema validation, host/scope selectors, event application, directory loading."""
import copy
import json
import random

import pytest

from fleetgate.fleet import Fleet
from fleetgate.scenarios import (
    Scenario,
    apply_event,
    get_scenario,
    load_scenario,
    load_scenarios,
    resolve_host,
    resolve_scope,
    scenario_dir,
)
from fleetgate.schema import SchemaError

BASE = {
    "name": "memory_leak_ramp",
    "description": "slow leak",
    "fleet": {"hosts": 30, "seed": 7, "load": {"period": 48, "amplitude": 0.3}},
    "ticks": 40,
    "events": [{"tick": 3, "type": "inject", "host": {"role": "worker", "nth": 0}, "fault": "memory_leak"}],
    "policy": "default",
    "tags": ["software"],
}


def scen(**over):
    d = copy.deepcopy(BASE)
    d.update(over)
    return d


def test_valid_scenario_roundtrips_and_exposes_helpers():
    s = Scenario.from_dict(BASE)
    assert s.name == "memory_leak_ramp" and s.ticks == 40 and s.policy == "default" and s.faults == ["memory_leak"]
    assert s.events_at(3) == s.events and s.events_at(4) == []
    assert Scenario.from_dict(s.to_dict()).to_dict() == s.to_dict()
    assert len(s.build_fleet().hosts) == 30
    withx = Scenario.from_dict(scen(expect={"min_detected": 1}))
    assert withx.to_dict()["expect"] == {"min_detected": 1}


@pytest.mark.parametrize("patch,needle", [
    ({"name": "Has Spaces"}, "does not match"),
    ({"ticks": 0}, "minimum"),
    ({"ticks": "forty"}, "expected integer"),
    ({"fleet": {"hosts": 0}}, "minimum"),
    ({"fleet": {"warp": 9}}, "unexpected property"),
    ({"fleet": {"load": {"amplitude": -1}}}, "minimum"),
    ({"events": [{"tick": -1, "type": "inject"}]}, "minimum"),
    ({"events": [{"tick": 1, "type": "teleport"}]}, "not one of"),
    ({"events": [{"tick": 1, "type": "inject", "host": "h001", "fault": "memory_leak", "bogus": 1}]},
     "unexpected property"),
    ({"events": [{"tick": 1, "type": "inject", "host": "h001"}]}, "inject needs host and fault"),
    ({"events": [{"tick": 1, "type": "inject", "host": "h001", "fault": "gremlins"}]}, "unknown fault"),
    ({"events": [{"tick": 1, "type": "inject_rack"}]}, "needs 'rack'"),
    ({"events": [{"tick": 1, "type": "inject_zone", "zone": "random", "fault": "pdu_failure_x"}]},
     "unknown group fault"),
    ({"events": [{"tick": 1, "type": "inject_random", "faults": ["nope"]}]}, "unknown faults"),
    ({"events": [{"tick": 1, "type": "clear", "host": "h001"}]}, "clear needs host and fault"),
    ({"events": [{"tick": 1, "type": "inject", "host": "h001", "fault": "thermal", "duty": 2}]}, "maximum"),
])
def test_invalid_scenarios_are_rejected_with_a_useful_message(patch, needle):
    with pytest.raises((SchemaError, ValueError)) as ei:
        Scenario.from_dict(scen(**patch))
    assert needle in str(ei.value)


def test_missing_required_sections():
    for key in ("name", "fleet", "ticks", "events"):
        d = copy.deepcopy(BASE)
        del d[key]
        with pytest.raises(SchemaError, match="missing required"):
            Scenario.from_dict(d)


# ---- selectors -------------------------------------------------------------------------------------------


def test_resolve_host_selectors():
    f = Fleet(30, seed=2)
    rng = random.Random(0)
    assert resolve_host(f, "h005", rng) == "h005"
    assert resolve_host(f, "random", rng) in f.hosts
    workers = [h.id for h in f.hosts.values() if h.role == "worker"]
    assert resolve_host(f, {"role": "worker", "nth": 1}, rng) == workers[1]
    assert resolve_host(f, {"role": "worker", "nth": len(workers) + 1}, rng) == workers[1]  # wraps
    assert f.hosts[resolve_host(f, {"roles": ["cache", "ingress"]}, rng)].role in ("cache", "ingress")
    assert f.hosts[resolve_host(f, {"role": "worker", "random": True}, rng)].role == "worker"
    with pytest.raises(ValueError, match="unknown host"):
        resolve_host(f, "h999", rng)
    with pytest.raises(ValueError, match="no host matches"):
        resolve_host(f, {"role": "mainframe"}, rng)
    f.hosts[workers[0]].decommissioned = True
    assert resolve_host(f, {"role": "worker", "nth": 0}, rng) == workers[1]


def test_resolve_scope_selectors():
    f = Fleet(40, seed=2)
    rng = random.Random(0)
    racks = sorted(f.topology.racks)
    assert resolve_scope(f, "rack", racks[1], rng) == racks[1]
    assert resolve_scope(f, "rack", {"index": 2}, rng) == racks[2]
    assert resolve_scope(f, "rack", {"index": 6}, rng) == racks[2]  # wraps
    assert resolve_scope(f, "zone", "random", rng) in f.topology.zones
    assert resolve_scope(f, "pdu", {"index": 0}, rng) == f.topology.pdus[0]
    with pytest.raises(ValueError, match="unknown rack"):
        resolve_scope(f, "rack", "rack-404", rng)


# ---- event application ---------------------------------------------------------------------------------


def test_apply_inject_and_clear_and_modes():
    f = Fleet(30, seed=2)
    rng = random.Random(0)
    rec = apply_event(f, {"tick": 1, "type": "inject", "host": "h003", "fault": "link_flap", "mode": "ramp",
                          "ramp_ticks": 8}, rng)
    assert rec == {"type": "inject", "host": "h003", "fault": "link_flap"}
    af = f.hosts["h003"].faults["link_flap"]
    assert af.mode == "ramp" and af.ramp_ticks == 8
    apply_event(f, {"tick": 2, "type": "clear", "host": "h003", "fault": "link_flap"}, rng)
    assert not f.hosts["h003"].faults


def test_apply_group_events():
    f = Fleet(40, seed=2)
    rng = random.Random(0)
    r = apply_event(f, {"tick": 1, "type": "inject_rack", "rack": {"index": 0}}, rng)
    assert r["scope"] == "rack" and r["fault"] == "tor_switch_failure" and len(r["hosts"]) == 10
    z = apply_event(f, {"tick": 1, "type": "inject_zone", "zone": {"index": 1}}, rng)
    assert z["fault"] == "cooling_failure" and len(z["hosts"]) == 20
    p = apply_event(f, {"tick": 1, "type": "inject_pdu", "pdu": "random"}, rng)
    assert p["fault"] == "pdu_failure" and p["scope"] == "pdu"
    assert all("psu_failure" in f.hosts[h].faults for h in p["hosts"])


def test_apply_inject_random_clear_all_and_set_load():
    f = Fleet(30, seed=2)
    rng = random.Random(3)
    r = apply_event(f, {"tick": 1, "type": "inject_random", "count": 4, "faults": ["service_down", "nic_errors"],
                        "roles": ["worker"]}, rng)
    assert 1 <= len(r["injected"]) <= 4 and all(f.hosts[i["host"]].role == "worker" for i in r["injected"])
    empty = apply_event(f, {"tick": 1, "type": "inject_random", "count": 2, "roles": ["mainframe"]}, rng)
    assert empty["injected"] == []
    assert apply_event(f, {"tick": 2, "type": "clear_all"}, rng) == {"type": "clear_all"}
    assert not f.faulty_hosts()
    ld = apply_event(f, {"tick": 3, "type": "set_load", "amplitude": 0.5, "period_ticks": 24}, rng)
    assert ld == {"type": "set_load", "amplitude": 0.5, "period": 24} and f.load.period == 24


def test_apply_unknown_event_type_is_an_error():
    with pytest.raises(ValueError, match="unknown event type"):
        apply_event(Fleet(10), {"tick": 1, "type": "meteor"}, random.Random(0))


# ---- loading ---------------------------------------------------------------------------------------------


def test_load_scenarios_from_a_directory(tmp_path):
    for i in range(3):
        (tmp_path / f"s{i}.json").write_text(json.dumps(scen(name=f"scn_{i}")))
    found = load_scenarios(tmp_path)
    assert list(found) == ["scn_0", "scn_1", "scn_2"]
    assert get_scenario("scn_1", tmp_path).name == "scn_1"
    assert load_scenario(tmp_path / "s2.json").name == "scn_2"
    assert get_scenario(str(tmp_path / "s0.json")).name == "scn_0"
    with pytest.raises(KeyError, match="unknown scenario 'nope'; known: scn_0, scn_1, scn_2"):
        get_scenario("nope", tmp_path)


def test_duplicate_names_and_broken_files_are_reported(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(scen()))
    (tmp_path / "b.json").write_text(json.dumps(scen()))
    with pytest.raises(ValueError, match="duplicate scenario name"):
        load_scenarios(tmp_path)
    (tmp_path / "b.json").write_text(json.dumps(scen(name="other", ticks=-5)))
    with pytest.raises(SchemaError):
        load_scenarios(tmp_path)
    (tmp_path / "b.json").write_text("{ not json")
    with pytest.raises(json.JSONDecodeError):
        load_scenarios(tmp_path)


def test_scenario_dir_resolution_order(tmp_path, monkeypatch):
    monkeypatch.delenv("FLEETGATE_SCENARIO_DIR", raising=False)
    assert scenario_dir(tmp_path) == tmp_path
    monkeypatch.setenv("FLEETGATE_SCENARIO_DIR", str(tmp_path / "env"))
    assert scenario_dir() == tmp_path / "env"
    assert scenario_dir(tmp_path) == tmp_path  # explicit argument wins
    monkeypatch.delenv("FLEETGATE_SCENARIO_DIR")
    assert scenario_dir().name == "scenarios"
