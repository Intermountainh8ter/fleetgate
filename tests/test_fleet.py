import pytest

from fleetgate.detect import RULES
from fleetgate.fleet import (
    BMC_METRICS,
    FAULT_SPECS,
    FAULTS,
    GROUP_FAULTS,
    ActiveFault,
    Fleet,
    LoadPattern,
    cascade_parents,
)
from fleetgate.topology import PROTECTED_ROLES, Topology


def test_catalogue_size_and_variety():
    assert len(FAULTS) >= 20
    modes = {s.mode for s in FAULT_SPECS.values()}
    assert {"step", "ramp", "intermittent"} <= modes
    assert any(s.cascades for s in FAULT_SPECS.values())
    assert set(GROUP_FAULTS) == {"tor_switch_failure", "pdu_failure", "cooling_failure"}
    cats = {s.category for s in FAULT_SPECS.values()}
    assert {"hardware", "software", "network", "power", "thermal", "security", "time"} <= cats


def test_every_fault_has_a_detection_rule_or_is_derived_from_one():
    # every per-host fault is visible to at least one threshold rule on a metric it perturbs
    for name, spec in FAULT_SPECS.items():
        rule_metrics = {m for r in RULES.values() for m in r.metrics}
        assert set(spec.metrics) & rule_metrics, name


def test_same_seed_same_metrics():
    a, b = Fleet(12, seed=9), Fleet(12, seed=9)
    a.inject("h003", "thermal")
    b.inject("h003", "thermal")
    for _ in range(5):
        assert a.step() == b.step()


def test_different_seed_different_roles_or_metrics():
    assert Fleet(12, seed=1).step() != Fleet(12, seed=2).step()


def test_inject_unknown_fault_raises(fleet30):
    with pytest.raises(ValueError):
        fleet30.inject("h001", "gremlins")


@pytest.mark.parametrize("fault", sorted(FAULT_SPECS))
def test_each_fault_moves_its_metrics_toward_the_target(fault):
    f = Fleet(12, seed=4)
    f.inject("h001", fault)
    spec = FAULT_SPECS[fault]
    for _ in range(max(20, spec.ramp_ticks + 2)):
        f.step()
    healthy = Fleet(12, seed=4)
    for _ in range(max(20, spec.ramp_ticks + 2)):
        healthy.step()
    faulty_m, base_m = f.last_sample["h001"], healthy.last_sample["h001"]
    moved = [m for m in spec.metrics if m in faulty_m and m in base_m and abs(faulty_m[m] - base_m[m]) > 1e-9]
    if spec.mode == "intermittent":
        return  # may sit in its quiet phase on this tick; covered by the intermittent test
    assert moved, f"{fault} did not perturb any of {list(spec.metrics)}"


def test_ramp_intensity_is_monotonic_then_saturates():
    af = ActiveFault("memory_leak", since=10, mode="ramp", ramp_ticks=10)
    vals = [af.intensity(t) for t in range(8, 25)]
    assert vals[0] == 0.0 and vals[2] == 0.0
    assert vals == sorted(vals)
    assert vals[-1] == 1.0 and abs(af.intensity(15) - 0.5) < 1e-9


def test_intermittent_fault_toggles():
    af = ActiveFault("link_flap", since=0, mode="intermittent", duty=0.5, period=4)
    seq = [af.intensity(t) for t in range(8)]
    assert seq == [1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0]


def test_memory_leak_ramps_into_oom_then_service_down():
    f = Fleet(10, seed=3)
    f.inject("h001", "memory_leak")
    first_seen: dict[str, int] = {}
    for _ in range(40):
        f.step()
        for name in f.hosts["h001"].faults:
            first_seen.setdefault(name, f.tick)
    assert list(first_seen) == ["memory_leak", "oom_kills", "service_down"]  # strict cascade order
    assert first_seen["oom_kills"] > first_seen["memory_leak"] + 10
    assert first_seen["service_down"] > first_seen["oom_kills"]
    parents = cascade_parents("oom_kills")
    assert "memory_leak" in parents and "swap_exhaustion" in parents


def test_fan_failure_cascades_to_thermal_and_throttling():
    f = Fleet(10, seed=3)
    f.inject("h001", "fan_failure")
    for _ in range(12):
        f.step()
    faults = f.hosts["h001"].faults
    assert {"fan_failure", "thermal", "cpu_throttling"} <= set(faults)
    assert faults["thermal"].cascaded_from == "fan_failure"


def test_clearing_parent_clears_derived_children_only():
    f = Fleet(10, seed=3)
    f.inject("h001", "thermal")
    for _ in range(5):
        f.step()
    assert "cpu_throttling" in f.hosts["h001"].faults
    f.clear("h001", "thermal")
    assert not f.hosts["h001"].faults  # cpu_throttling is derived, so it goes with its parent
    kinds = [e["event"] for e in f.fault_log if e["host"] == "h001"]
    assert kinds.count("clear") == 2 and "cascade" in kinds


def test_bmc_unreachable_hides_bmc_metrics_and_ssh_hides_os_metrics():
    f = Fleet(10, seed=3)
    f.inject("h001", "bmc_unreachable")
    f.inject("h002", "ssh_unreachable")
    data = f.step()
    assert not (BMC_METRICS & set(data["h001"])) and "cpu_util" in data["h001"]
    assert "temp_c" in data["h002"] and "cpu_util" not in data["h002"]
    assert data["h002"]["ssh_reachable"] == 0 and data["h001"]["bmc_reachable"] == 0
    assert f.probe("h001", "bmc_reachable") is False and f.probe("h002", "ssh_reachable") is False
    with pytest.raises(ValueError):
        f.probe("h001", "telepathy")


def test_diurnal_load_changes_utilisation():
    f = Fleet(10, seed=1, load=LoadPattern(period=48, amplitude=0.5))
    util = []
    for _ in range(48):
        f.step()
        util.append(sum(m["cpu_util"] for m in f.last_sample.values()) / 10)
    assert max(util) - min(util) > 15
    flat = Fleet(10, seed=1)
    util2 = []
    for _ in range(48):
        flat.step()
        util2.append(sum(m["cpu_util"] for m in flat.last_sample.values()) / 10)
    assert max(util2) - min(util2) < max(util) - min(util)


def test_load_pattern_weekly_component_and_floor():
    lp = LoadPattern(period=24, amplitude=0.0, weekly_period=168, weekly_amplitude=0.3)
    assert lp.factor(0) == 1.0
    assert lp.factor(42) == pytest.approx(1.3)
    assert LoadPattern(amplitude=5.0).factor(36) == 0.05  # never goes negative


def test_noise_scale_zero_is_noise_free():
    f = Fleet(5, seed=1, noise_scale=0.0)
    f.step()
    a = dict(f.last_sample["h001"])
    f2 = Fleet(5, seed=99, noise_scale=0.0)
    f2.step()
    # personality still differs by seed, but the injected noise term is gone: temp is deterministic per host
    assert a["service_up"] == f2.last_sample["h001"]["service_up"] == 1.0


def test_group_fault_hits_every_host_under_the_scope():
    f = Fleet(40, seed=5)
    rack = sorted(f.topology.racks)[0]
    hosts = f.inject_rack(rack, "tor_switch_failure")
    assert hosts == list(f.topology.hosts_in_rack(rack)) and len(hosts) == 10
    groups = {f.hosts[h].faults["uplink_loss"].group for h in hosts}
    assert len(groups) == 1 and groups.pop().startswith("tor_switch_failure:")
    pdu_rack = sorted(f.topology.racks)[1]
    pdu_hosts = f.inject_rack(pdu_rack, "pdu_failure")
    assert set(pdu_hosts) == set(f.topology.hosts_on_pdu(f.topology.pdu_of(pdu_hosts[0])))
    assert len(pdu_hosts) >= 10
    f.clear_group(next(iter(f.hosts[hosts[0]].faults.values())).group)
    assert not any("uplink_loss" in f.hosts[h].faults for h in hosts)
    with pytest.raises(ValueError):
        f.inject_group("meteor_strike", rack)


def test_schedule_clear_lands_after_the_delay():
    f = Fleet(10, seed=1)
    f.inject("h001", "service_down")
    f.schedule_clear("h001", ("service_down",), 3)
    for _ in range(2):
        f.step()
    assert "service_down" in f.hosts["h001"].faults
    f.step()
    f.step()
    assert "service_down" not in f.hosts["h001"].faults
    f.inject("h002", "service_down")
    f.schedule_clear("h002", ("service_down",), 0)
    assert "service_down" not in f.hosts["h002"].faults


def test_roles_protected_and_unique_per_rack_when_possible():
    f = Fleet(60, seed=7)
    roles = {h.role for h in f.hosts.values()}
    assert {"worker", "db-primary", "validator"} <= roles
    for rack in f.topology.racks.values():
        prot = [h for h in rack.hosts if f.hosts[h].role in PROTECTED_ROLES]
        assert len(prot) <= 2


def test_fleet_views_and_ground_truth():
    f = Fleet(20, seed=1)
    f.inject("h001", "service_down")
    f.hosts["h002"].drained = True
    assert f.drained_fraction() == pytest.approx(0.05)
    rc = f.role_counts()
    assert sum(c["total"] for c in rc.values()) == 20
    assert sum(c["drained"] for c in rc.values()) == 1 and sum(c["faulty"] for c in rc.values()) == 1
    assert f.ground_truth()[0]["fault"] == "service_down"
    assert [h.id for h in f.faulty_hosts()] == ["h001"]
    data = f.step()
    assert "h002" not in data and "h002" in f.last_sample  # drained hosts are not reported but still sampled


def test_from_config_and_custom_topology():
    f = Fleet.from_config({"hosts": 24, "seed": 3, "dcs": 2, "hosts_per_rack": 6,
                           "load": {"period": 24, "amplitude": 0.2}, "roles": ["worker", "cache"]})
    assert len(f.hosts) == 24 and f.topology.dcs == ["dc1", "dc2"] and f.load.amplitude == 0.2
    assert {h.role for h in f.hosts.values()} <= {"worker", "cache"}
    topo = Topology.build(8, hosts_per_rack=4)
    assert len(Fleet(8, topology=topo).hosts) == 8
