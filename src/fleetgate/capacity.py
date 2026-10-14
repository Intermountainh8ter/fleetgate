"""CapacityAgent: recommend spare capacity per role from observed drain rates.

Deterministic arithmetic over fleet state and the executed-action history: how fast hosts are
being drained, how much headroom the blast-radius cap leaves, and how many spare hosts are needed
to keep that headroom over a lead time (how long it takes DC-ops to return a host).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .fleet import Fleet
from .policy import PolicyConfig


@dataclass
class RoleCapacity:
    role: str
    total: int
    active: int
    drained: int
    faulty: int
    drain_rate: float  # drains per tick over the window
    headroom: int  # more hosts that may be drained before the fleet-wide cap bites
    ticks_until_cap: float | None
    projected_drained: float  # drained after lead_time at current rate
    recommended_spare: int

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "total": self.total, "active": self.active, "drained": self.drained,
                "faulty": self.faulty, "drain_rate": round(self.drain_rate, 4), "headroom": self.headroom,
                "ticks_until_cap": None if self.ticks_until_cap is None else round(self.ticks_until_cap, 1),
                "projected_drained": round(self.projected_drained, 2), "recommended_spare": self.recommended_spare}


@dataclass
class CapacityReport:
    tick: int
    window_ticks: int
    lead_time_ticks: int
    fleet_total: int
    fleet_drained: int
    cap_fraction: float
    cap_hosts: int
    fleet_drain_rate: float
    ticks_until_cap: float | None
    roles: list[RoleCapacity] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"tick": self.tick, "window_ticks": self.window_ticks, "lead_time_ticks": self.lead_time_ticks,
                "fleet_total": self.fleet_total, "fleet_drained": self.fleet_drained, "cap_fraction": self.cap_fraction,
                "cap_hosts": self.cap_hosts, "fleet_drain_rate": round(self.fleet_drain_rate, 4),
                "ticks_until_cap": None if self.ticks_until_cap is None else round(self.ticks_until_cap, 1),
                "roles": [r.to_dict() for r in self.roles], "recommendations": self.recommendations}

    def text(self) -> str:
        lines = [f"capacity @ tick {self.tick}: {self.fleet_drained}/{self.fleet_total} drained "
                 f"(cap {self.cap_hosts} = {self.cap_fraction:.0%}), drain rate {self.fleet_drain_rate:.3f}/tick "
                 f"over {self.window_ticks} ticks, cap in "
                 f"{'never' if self.ticks_until_cap is None else f'{self.ticks_until_cap:.0f} ticks'}",
                 f"{'role':12} {'total':>5} {'active':>6} {'drained':>7} {'faulty':>6} {'rate':>7} {'spare+':>6}"]
        for r in self.roles:
            lines.append(f"{r.role:12} {r.total:5d} {r.active:6d} {r.drained:7d} {r.faulty:6d} {r.drain_rate:7.3f} "
                         f"{r.recommended_spare:6d}")
        lines += [f"- {x}" for x in self.recommendations]
        return "\n".join(lines)


class CapacityAgent:
    def __init__(self, fleet: Fleet, policy: PolicyConfig | None = None, window_ticks: int = 24,
                 lead_time_ticks: int = 48, safety_factor: float = 1.5):
        self.fleet, self.cfg = fleet, policy or PolicyConfig()
        self.window, self.lead, self.safety = window_ticks, lead_time_ticks, safety_factor

    def report(self, history: list[dict[str, Any]]) -> CapacityReport:
        """`history` is the policy's executed-action history (tick, runbook, host, role, dc)."""
        t = self.fleet.tick
        n = len(self.fleet.hosts)
        cap_hosts = math.floor(self.cfg.max_drained_fraction * n + 1e-9)
        drained_total = sum(not h.active for h in self.fleet.hosts.values())
        drains = [h for h in history if h["runbook"] in ("drain_host", "migrate_workloads") and t - h["tick"] < self.window]
        window = max(1, min(self.window, t)) if t else self.window
        fleet_rate = len(drains) / window
        headroom_fleet = max(0, cap_hosts - drained_total)
        ticks_fleet = (headroom_fleet / fleet_rate) if fleet_rate > 0 else None
        roles: list[RoleCapacity] = []
        recs: list[str] = []
        for role, c in sorted(self.fleet.role_counts().items()):
            rate = sum(1 for h in drains if h["role"] == role) / window
            projected = c["drained"] + rate * self.lead
            headroom = max(0, headroom_fleet)
            floor = self.cfg.min_active_per_role.get(role, 0)
            headroom_role = max(0, c["active"] - floor)
            headroom = min(headroom, headroom_role)
            ticks = (headroom / rate) if rate > 0 else None
            need = math.ceil(max(0.0, projected - c["drained"] - headroom) * self.safety)
            if c["active"] - floor <= 0 and c["total"]:
                need = max(need, 1)
            roles.append(RoleCapacity(role, c["total"], c["active"], c["drained"], c["faulty"], rate, headroom, ticks,
                                      projected, need))
            if need:
                recs.append(f"{role}: add {need} spare host(s); at {rate:.3f} drains/tick the cap is reached in "
                            f"{'<1' if ticks is not None and ticks < 1 else (f'{ticks:.0f}' if ticks is not None else 'n/a')} ticks "
                            f"and DC-ops lead time is {self.lead} ticks")
            elif c["faulty"] > c["drained"]:
                recs.append(f"{role}: {c['faulty'] - c['drained']} faulty host(s) still serving; drain capacity available ({headroom})")
        if drained_total > cap_hosts:
            recs.append(f"fleet is over the drain cap ({drained_total} > {cap_hosts}): no further drains will be allowed")
        if not recs:
            recs.append("no action: drain rate is within headroom for the lead time")
        return CapacityReport(t, self.window, self.lead, n, drained_total, self.cfg.max_drained_fraction, cap_hosts,
                              fleet_rate, ticks_fleet, roles, recs)
