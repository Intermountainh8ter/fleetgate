from fleetgate.correlate import HYPOTHESES, Correlator, hypothesis_for
from fleetgate.detect import Incident
from fleetgate.topology import Topology


def inc(host, signal, tick, i=None):
    return Incident(f"inc-{host}-{signal}-{tick}", host, signal, tick)


def topo():
    return Topology.build(40, hosts_per_rack=10)


def test_hypothesis_lookup_by_signal_and_by_metric():
    assert hypothesis_for("uplink_loss") == ("rack", "tor_switch_failure")
    assert hypothesis_for("ewma:psu_ok") == ("pdu", "pdu_failure")
    assert hypothesis_for("seasonal:temp_c") == ("zone", "cooling_failure")
    assert hypothesis_for("service_down") is None and hypothesis_for("ewma:cpu_util") is None
    assert HYPOTHESES["ntp_drift"][0] == "dc"


def test_rack_wide_loss_becomes_one_group_incident():
    t = topo()
    c = Correlator(t)
    rack = next(iter(t.racks.values()))
    ins = [inc(h, "uplink_loss", 5) for h in rack.hosts]
    groups, singles = c.correlate(5, ins, set(t.hosts))
    assert len(groups) == 1 and singles == []
    g = groups[0]
    assert g.scope == "rack" and g.scope_id == rack.id and g.hypothesis == "tor_switch_failure"
    assert g.hosts == sorted(rack.hosts) and g.fraction == 1.0 and len(g.members) == 10
    assert g.host == g.hosts[0] and g.evidence["hosts_affected"] == 10.0 and g.signals == ["uplink_loss"]


def test_two_hosts_in_a_rack_stay_standalone_below_min_hosts():
    t = topo()
    c = Correlator(t)
    rack = next(iter(t.racks.values()))
    ins = [inc(h, "uplink_loss", 5) for h in rack.hosts[:2]]
    groups, singles = c.correlate(5, ins, set(t.hosts))
    assert groups == [] and len(singles) == 2


def test_unrelated_signals_never_group():
    t = topo()
    c = Correlator(t)
    rack = next(iter(t.racks.values()))
    ins = [inc(h, "service_down", 5) for h in rack.hosts]
    groups, singles = c.correlate(5, ins, set(t.hosts))
    assert groups == [] and len(singles) == 10


def test_incidents_spread_across_racks_do_not_group():
    t = topo()
    c = Correlator(t)
    racks = list(t.racks.values())
    ins = [inc(racks[i].hosts[0], "uplink_loss", 5) for i in range(4)]
    groups, singles = c.correlate(5, ins, set(t.hosts))
    assert groups == [] and len(singles) == 4


def test_incidents_arriving_across_the_window_still_group():
    t = topo()
    c = Correlator(t, window_ticks=3)
    rack = next(iter(t.racks.values()))
    g1, s1 = c.correlate(5, [inc(rack.hosts[0], "uplink_loss", 5), inc(rack.hosts[1], "uplink_loss", 5)], set(t.hosts))
    assert g1 == [] and len(s1) == 2
    g2, s2 = c.correlate(7, [inc(rack.hosts[2], "uplink_loss", 7)], set(t.hosts))
    assert len(g2) == 1 and len(g2[0].hosts) == 3 and len(g2[0].members) == 3


def test_window_expiry_forgets_old_incidents():
    t = topo()
    c = Correlator(t, window_ticks=2)
    rack = next(iter(t.racks.values()))
    c.correlate(5, [inc(rack.hosts[0], "uplink_loss", 5), inc(rack.hosts[1], "uplink_loss", 5)], set(t.hosts))
    groups, _ = c.correlate(12, [inc(rack.hosts[2], "uplink_loss", 12)], set(t.hosts))
    assert groups == []


def test_stragglers_are_absorbed_into_the_open_group():
    t = topo()
    c = Correlator(t)
    rack = next(iter(t.racks.values()))
    groups, _ = c.correlate(5, [inc(h, "uplink_loss", 5) for h in rack.hosts[:5]], set(t.hosts))
    g = groups[0]
    late = inc(rack.hosts[7], "packet_loss", 9)
    groups2, singles2 = c.correlate(9, [late], set(t.hosts))
    assert groups2 == [] and singles2 == []  # consumed by the existing group
    assert rack.hosts[7] in g.hosts and set(g.signals) == {"uplink_loss", "packet_loss"} and "+" in g.signal
    assert c.group_for_host(rack.hosts[7], 10) is g and c.group_for_host(rack.hosts[7], 999) is None
    assert c.group_for_host("h039", 10) is None


def test_zone_and_pdu_scopes():
    t = topo()
    c = Correlator(t, min_hosts=3, min_fraction=0.25)
    racks = list(t.racks.values())
    zone_hosts = racks[0].hosts[:3] + racks[1].hosts[:3]  # two racks sharing a cooling zone
    groups, _ = c.correlate(4, [inc(h, "thermal", 4) for h in zone_hosts], set(t.hosts))
    assert len(groups) == 1 and groups[0].scope == "zone" and groups[0].hypothesis == "cooling_failure"
    assert groups[0].fraction == 6 / 20
    c2 = Correlator(t)
    pdu_hosts = racks[2].hosts + racks[3].hosts[:5]
    groups2, _ = c2.correlate(4, [inc(h, "psu_failure", 4) for h in pdu_hosts], set(t.hosts))
    assert groups2[0].scope == "pdu" and groups2[0].hypothesis == "pdu_failure"


def test_fraction_uses_active_hosts_only():
    t = topo()
    c = Correlator(t, min_hosts=3, min_fraction=0.5)
    rack = next(iter(t.racks.values()))
    ins = [inc(h, "uplink_loss", 5) for h in rack.hosts[:3]]
    assert c.correlate(5, ins, set(t.hosts))[0] == []  # 3/10 < 50%
    c2 = Correlator(t, min_hosts=3, min_fraction=0.5)
    active = set(rack.hosts[:5])  # the other five are drained: 3 of 5 active hosts are affected
    assert len(c2.correlate(5, ins, active)[0]) == 1


def test_unknown_host_is_ignored_by_grouping():
    t = topo()
    c = Correlator(t)
    ghost = inc("zzz", "uplink_loss", 5)
    groups, singles = c.correlate(5, [ghost], set(t.hosts))
    assert groups == [] and singles == [ghost]
    assert c._absorb(5, ghost) is False


def test_an_unresolved_group_keeps_absorbing_late_symptoms():
    t = topo()
    rack = next(iter(t.racks.values()))
    open_state = {"open": True}
    c = Correlator(t, absorb_ticks=5, is_open=lambda g: open_state["open"])
    g = c.correlate(5, [inc(h, "uplink_loss", 5) for h in rack.hosts[:4]], set(t.hosts))[0][0]
    late = inc(rack.hosts[8], "link_flap", 40)  # far outside the absorb window
    groups, singles = c.correlate(40, [late], set(t.hosts))
    assert groups == [] and singles == [] and rack.hosts[8] in g.hosts
    open_state["open"] = False
    groups, singles = c.correlate(60, [inc(rack.hosts[9], "link_flap", 60)], set(t.hosts))
    assert singles and groups == []  # once the group is resolved a new symptom is a new, standalone incident
