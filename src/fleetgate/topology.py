"""Fleet topology: datacenters > rooms > racks > hosts, with shared infrastructure per rack.

Every rack has a top-of-rack switch (ToR). Racks share a PDU in pairs and a cooling zone in pairs,
so a single PDU or CRAC failure hits several racks at once. The topology is pure data; the
simulator (`fleet.py`) places hosts on it and the correlation engine (`correlate.py`) and
RootCauseAgent use it to turn N host incidents into one rack- or zone-level incident.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

ROLES = ("worker", "cache", "db-primary", "db-replica", "validator", "gpu-worker", "storage", "ingress")
ROLE_WEIGHTS = {"worker": 50, "cache": 12, "db-primary": 4, "db-replica": 6, "validator": 6,
                "gpu-worker": 10, "storage": 8, "ingress": 4}
PROTECTED_ROLES = frozenset({"db-primary", "validator"})


@dataclass(frozen=True)
class Rack:
    id: str
    room: str
    dc: str
    zone: str  # cooling zone (shared CRAC unit)
    pdu: str
    tor: str
    hosts: tuple[str, ...]


class Topology:
    def __init__(self, racks: dict[str, Rack]):
        self.racks = dict(racks)
        self.host_rack: dict[str, str] = {h: r.id for r in self.racks.values() for h in r.hosts}

    # ---- construction -------------------------------------------------------------------------
    @classmethod
    def build(cls, n_hosts: int, dcs: int = 1, rooms_per_dc: int = 1, hosts_per_rack: int = 10,
              racks_per_zone: int = 2, racks_per_pdu: int = 2, host_prefix: str = "h") -> Topology:
        if n_hosts <= 0:
            raise ValueError("n_hosts must be positive")
        hosts_per_rack = max(1, hosts_per_rack)
        n_racks = math.ceil(n_hosts / hosts_per_rack)
        racks_per_room = max(1, math.ceil(n_racks / max(1, dcs * rooms_per_dc)))
        racks: dict[str, Rack] = {}
        for k in range(n_racks):
            dc_i = k // (rooms_per_dc * racks_per_room)
            room_i = (k // racks_per_room) % rooms_per_dc
            rk_i = k % racks_per_room
            dc = f"dc{dc_i + 1}"
            room = f"{dc}-rm{room_i + 1}"
            rack_id = f"{room}-rk{rk_i + 1:02d}"
            zone = f"{room}-cz{rk_i // racks_per_zone + 1}"
            pdu = f"{room}-pdu{rk_i // racks_per_pdu + 1}"
            hosts = tuple(f"{host_prefix}{i:03d}" for i in range(k * hosts_per_rack,
                                                                  min(n_hosts, (k + 1) * hosts_per_rack)))
            racks[rack_id] = Rack(rack_id, room, dc, zone, pdu, f"tor-{rack_id}", hosts)
        return cls(racks)

    # ---- lookups ------------------------------------------------------------------------------
    def rack_of(self, host: str) -> Rack:
        return self.racks[self.host_rack[host]]

    def dc_of(self, host: str) -> str:
        return self.rack_of(host).dc

    def room_of(self, host: str) -> str:
        return self.rack_of(host).room

    def zone_of(self, host: str) -> str:
        return self.rack_of(host).zone

    def pdu_of(self, host: str) -> str:
        return self.rack_of(host).pdu

    def hosts_in_rack(self, rack_id: str) -> tuple[str, ...]:
        return self.racks[rack_id].hosts

    def racks_in_zone(self, zone: str) -> list[Rack]:
        return [r for r in self.racks.values() if r.zone == zone]

    def racks_on_pdu(self, pdu: str) -> list[Rack]:
        return [r for r in self.racks.values() if r.pdu == pdu]

    def hosts_in_zone(self, zone: str) -> list[str]:
        return [h for r in self.racks_in_zone(zone) for h in r.hosts]

    def hosts_on_pdu(self, pdu: str) -> list[str]:
        return [h for r in self.racks_on_pdu(pdu) for h in r.hosts]

    def hosts_in_dc(self, dc: str) -> list[str]:
        return [h for r in self.racks.values() if r.dc == dc for h in r.hosts]

    @property
    def hosts(self) -> list[str]:
        return [h for r in self.racks.values() for h in r.hosts]

    @property
    def dcs(self) -> list[str]:
        return sorted({r.dc for r in self.racks.values()})

    @property
    def rooms(self) -> list[str]:
        return sorted({r.room for r in self.racks.values()})

    @property
    def zones(self) -> list[str]:
        return sorted({r.zone for r in self.racks.values()})

    @property
    def pdus(self) -> list[str]:
        return sorted({r.pdu for r in self.racks.values()})

    def scope_hosts(self, scope: str, scope_id: str) -> list[str]:
        """Hosts under a named scope: rack | zone | pdu | dc | room."""
        if scope == "rack":
            return list(self.hosts_in_rack(scope_id))
        if scope == "zone":
            return self.hosts_in_zone(scope_id)
        if scope == "pdu":
            return self.hosts_on_pdu(scope_id)
        if scope == "dc":
            return self.hosts_in_dc(scope_id)
        if scope == "room":
            return [h for r in self.racks.values() if r.room == scope_id for h in r.hosts]
        raise ValueError(f"unknown scope {scope!r}")

    # ---- serialisation ------------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {"racks": [{"id": r.id, "room": r.room, "dc": r.dc, "zone": r.zone, "pdu": r.pdu,
                           "tor": r.tor, "hosts": list(r.hosts)} for r in self.racks.values()]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Topology:
        racks = {r["id"]: Rack(r["id"], r["room"], r["dc"], r["zone"], r["pdu"], r["tor"], tuple(r["hosts"]))
                 for r in d["racks"]}
        return cls(racks)

    def ascii(self) -> str:
        lines = []
        for dc in self.dcs:
            lines.append(dc)
            for room in sorted({r.room for r in self.racks.values() if r.dc == dc}):
                lines.append(f"  {room}")
                for r in sorted((r for r in self.racks.values() if r.room == room), key=lambda r: r.id):
                    lines.append(f"    {r.id}  zone={r.zone} pdu={r.pdu} hosts={r.hosts[0]}..{r.hosts[-1]} "
                                 f"({len(r.hosts)})")
        return "\n".join(lines)
