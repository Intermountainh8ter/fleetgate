"""Correlation engine: fold simultaneous per-host incidents into one rack/zone/PDU-level incident.

Ten hosts in one rack losing their uplink in the same two ticks is one ToR failure, not ten host
incidents. The correlator buffers newly opened incidents for `window_ticks`, groups them by
(shared-infrastructure scope, root-cause hypothesis) and, when enough of the scope is affected,
emits a `GroupIncident`. Member host incidents are consumed so the orchestrator handles the group
once instead of N times; stragglers that open a few ticks later on the same scope are absorbed
into the open group instead of becoming new incidents.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Incident, signal_metrics
from .topology import Topology

# signal -> (scope that shares the failure domain, hypothesis)
HYPOTHESES: dict[str, tuple[str, str]] = {
    "uplink_loss": ("rack", "tor_switch_failure"),
    "packet_loss": ("rack", "tor_switch_failure"),
    "link_flap": ("rack", "tor_switch_failure"),
    "nic_errors": ("rack", "tor_switch_failure"),
    "ssh_unreachable": ("rack", "tor_switch_failure"),
    "psu_failure": ("pdu", "pdu_failure"),
    "cooling_failure": ("zone", "cooling_failure"),
    "thermal": ("zone", "cooling_failure"),
    "cpu_throttling": ("zone", "cooling_failure"),
    "bmc_unreachable": ("rack", "management_network_failure"),
    "ntp_drift": ("dc", "ntp_source_failure"),
}
METRIC_HYPOTHESES: dict[str, tuple[str, str]] = {
    "packet_loss_pct": ("rack", "tor_switch_failure"), "link_flaps_per_h": ("rack", "tor_switch_failure"),
    "nic_crc_per_min": ("rack", "tor_switch_failure"), "psu_ok": ("pdu", "pdu_failure"),
    "temp_c": ("zone", "cooling_failure"), "fan_rpm": ("zone", "cooling_failure"),
    "cpu_mhz": ("zone", "cooling_failure"), "ntp_offset_ms": ("dc", "ntp_source_failure"),
    "bmc_reachable": ("rack", "management_network_failure"),
}


@dataclass
class GroupIncident:
    id: str
    scope: str  # rack | zone | pdu | dc
    scope_id: str
    signal: str  # "+"-joined member signals
    hypothesis: str
    hosts: list[str]
    opened_tick: int
    members: list[Incident] = field(default_factory=list)
    fraction: float = 0.0  # affected / hosts in scope
    severity: str = "critical"
    detector: str = "correlator"

    @property
    def host(self) -> str:  # representative host (lets group incidents flow through host-shaped code)
        return self.hosts[0]

    @property
    def evidence(self) -> dict[str, float]:
        return {"hosts_affected": float(len(self.hosts)), "fraction": round(self.fraction, 3)}

    @property
    def signals(self) -> list[str]:
        return sorted({m.signal for m in self.members})


def hypothesis_for(signal: str) -> tuple[str, str] | None:
    if signal in HYPOTHESES:
        return HYPOTHESES[signal]
    for metric in signal_metrics(signal):
        if metric in METRIC_HYPOTHESES:
            return METRIC_HYPOTHESES[metric]
    return None


class Correlator:
    def __init__(self, topology: Topology, min_hosts: int = 3, min_fraction: float = 0.25, window_ticks: int = 3,
                 absorb_ticks: int = 12):
        self.topo = topology
        self.min_hosts, self.min_fraction = min_hosts, min_fraction
        self.window, self.absorb = window_ticks, absorb_ticks
        self.buffer: list[Incident] = []  # recent host incidents not yet grouped
        self.groups: list[GroupIncident] = []
        self.grouped_ids: set[str] = set()

    def _scope_id(self, host: str, scope: str) -> str:
        rack = self.topo.rack_of(host)
        return {"rack": rack.id, "zone": rack.zone, "pdu": rack.pdu, "dc": rack.dc}[scope]

    def _scope_size(self, scope: str, scope_id: str, active_hosts: set[str] | None) -> int:
        hosts = self.topo.scope_hosts(scope, scope_id)
        if active_hosts is not None:
            hosts = [h for h in hosts if h in active_hosts]
        return max(1, len(hosts))

    def _absorb(self, tick: int, inc: Incident) -> bool:
        hyp = hypothesis_for(inc.signal)
        if hyp is None or inc.host not in self.topo.host_rack:
            return False
        scope, name = hyp
        scope_id = self._scope_id(inc.host, scope)
        for g in reversed(self.groups):
            if g.scope == scope and g.scope_id == scope_id and g.hypothesis == name \
                    and tick - g.opened_tick <= self.absorb:
                g.members.append(inc)
                if inc.host not in g.hosts:
                    g.hosts.append(inc.host)
                    g.hosts.sort()
                g.signal = "+".join(g.signals)
                self.grouped_ids.add(inc.id)
                return True
        return False

    def correlate(self, tick: int, incidents: list[Incident], active_hosts: set[str] | None = None,
                  ) -> tuple[list[GroupIncident], list[Incident]]:
        """Returns (new group incidents, host incidents that stay standalone)."""
        self.buffer = [i for i in self.buffer if tick - i.opened_tick <= self.window and i.id not in self.grouped_ids]
        fresh = [i for i in incidents if not self._absorb(tick, i)]
        self.buffer.extend(fresh)
        buckets: dict[tuple[str, str, str], list[Incident]] = {}
        for inc in self.buffer:
            hyp = hypothesis_for(inc.signal)
            if hyp is None or inc.host not in self.topo.host_rack:
                continue
            scope, name = hyp
            buckets.setdefault((scope, self._scope_id(inc.host, scope), name), []).append(inc)

        groups: list[GroupIncident] = []
        for (scope, scope_id, name), members in buckets.items():
            hosts = sorted({m.host for m in members})
            size = self._scope_size(scope, scope_id, active_hosts)
            frac = len(hosts) / size
            if len(hosts) >= self.min_hosts and frac >= self.min_fraction:
                g = GroupIncident(f"grp-{scope_id}-{name}-{tick}", scope, scope_id,
                                  "+".join(sorted({m.signal for m in members})), name, hosts, tick,
                                  list(members), frac)
                groups.append(g)
                self.groups.append(g)
                self.grouped_ids.update(m.id for m in members)
        standalone = [i for i in incidents if i.id not in self.grouped_ids]
        self.buffer = [i for i in self.buffer if i.id not in self.grouped_ids]
        return groups, standalone

    def group_for_host(self, host: str, tick: int) -> GroupIncident | None:
        for g in reversed(self.groups):
            if host in g.hosts and tick - g.opened_tick <= self.absorb:
                return g
        return None
