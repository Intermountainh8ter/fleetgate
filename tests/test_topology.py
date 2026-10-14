import pytest

from fleetgate.topology import Rack, Topology


def test_build_hierarchy_dc_room_rack_host():
    t = Topology.build(100, dcs=2, rooms_per_dc=2, hosts_per_rack=10)
    assert len(t.hosts) == 100 and len(set(t.hosts)) == 100
    assert t.dcs == ["dc1", "dc2"] and len(t.rooms) == 4 and len(t.racks) == 10
    h = t.hosts[0]
    rack = t.rack_of(h)
    assert rack.dc == "dc1" and rack.room.startswith("dc1-rm") and rack.id.startswith(rack.room)
    assert t.dc_of(h) == rack.dc and t.room_of(h) == rack.room and t.zone_of(h) == rack.zone
    assert t.pdu_of(h) == rack.pdu and rack.tor == f"tor-{rack.id}"


def test_every_host_is_in_exactly_one_rack_and_ids_are_stable():
    t = Topology.build(35, hosts_per_rack=10)
    assert [len(r.hosts) for r in t.racks.values()] == [10, 10, 10, 5]
    assert t.hosts == [f"h{i:03d}" for i in range(35)]
    assert Topology.build(35, hosts_per_rack=10).to_dict() == t.to_dict()


def test_racks_share_zones_and_pdus_in_pairs():
    t = Topology.build(40, hosts_per_rack=10)
    racks = list(t.racks.values())
    assert racks[0].zone == racks[1].zone != racks[2].zone
    assert racks[0].pdu == racks[1].pdu != racks[2].pdu
    assert len(t.racks_in_zone(racks[0].zone)) == 2 and len(t.racks_on_pdu(racks[0].pdu)) == 2
    assert len(t.hosts_in_zone(racks[0].zone)) == 20 and len(t.hosts_on_pdu(racks[2].pdu)) == 20


def test_scope_hosts_all_scopes_and_unknown():
    t = Topology.build(60, dcs=2, hosts_per_rack=10)
    rack = next(iter(t.racks.values()))
    assert t.scope_hosts("rack", rack.id) == list(rack.hosts)
    assert t.scope_hosts("zone", rack.zone) == t.hosts_in_zone(rack.zone)
    assert t.scope_hosts("pdu", rack.pdu) == t.hosts_on_pdu(rack.pdu)
    assert sorted(t.scope_hosts("dc", "dc1") + t.scope_hosts("dc", "dc2")) == sorted(t.hosts)
    assert set(t.scope_hosts("room", rack.room)) <= set(t.hosts_in_dc(rack.dc))
    with pytest.raises(ValueError):
        t.scope_hosts("galaxy", "x")


def test_roundtrip_serialisation_and_ascii():
    t = Topology.build(25, dcs=2, hosts_per_rack=5)
    t2 = Topology.from_dict(t.to_dict())
    assert t2.to_dict() == t.to_dict() and t2.host_rack == t.host_rack
    art = t.ascii()
    assert "dc1" in art and "dc2" in art and "zone=" in art and "h000..h004" in art


def test_build_rejects_empty_and_clamps_rack_size():
    with pytest.raises(ValueError):
        Topology.build(0)
    assert len(Topology.build(3, hosts_per_rack=0).racks) == 3


def test_manual_topology():
    r = Rack("r1", "rm1", "dc1", "cz1", "pdu1", "tor-r1", ("a", "b"))
    t = Topology({"r1": r})
    assert t.hosts == ["a", "b"] and t.hosts_in_rack("r1") == ("a", "b")
