"""Seeded bare-metal fleet simulator with injectable faults.

Design notes
------------
* Every host reports ~30 metrics per tick. Healthy values follow a diurnal load curve
  (`LoadPattern`) with heteroscedastic noise: the spread of utilisation-type metrics grows with load.
* Faults are declared as data (`FAULT_SPECS`): the metrics they push, how far, how noisily, their
  default onset mode (step / ramp / intermittent) and what they cascade into.
* Rack-level faults (ToR switch, PDU, cooling zone) inject one per-host fault on every host under
  that piece of shared infrastructure, tagged with a `group` id so detection evals can score a
  rack-level detection as one event.
* A BMC or SSH outage hides the metrics that would normally come through that path; detectors must
  cope with missing keys.
* The fleet is the "world": runbooks mutate it, the policy gate probes it for preconditions, and
  evals read `ground_truth()` for scoring. Agents never read ground truth.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any

from .topology import PROTECTED_ROLES, ROLE_WEIGHTS, ROLES, Topology

# --------------------------------------------------------------------------------------------
# Fault catalogue
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FaultSpec:
    name: str
    category: str  # hardware | software | network | power | thermal | security | time
    severity: str  # low | medium | high | critical
    metrics: dict[str, tuple[float, float]]  # metric -> (target value at full intensity, noise std)
    mode: str = "step"  # default onset: step | ramp | intermittent
    ramp_ticks: int = 0
    duty: float = 1.0  # intermittent: fraction of each period the fault is active
    period: int = 4
    cascades: tuple[tuple[str, int, float], ...] = ()  # (child fault, delay ticks, probability)
    hides: str | None = None  # "bmc" | "os": metrics unavailable while the fault is active
    derived: bool = False  # cleared automatically when its parent fault is cleared
    description: str = ""


FAULT_SPECS: dict[str, FaultSpec] = {s.name: s for s in [
    FaultSpec("thermal", "thermal", "high", {"temp_c": (93, 2.0), "fan_rpm": (2800, 200)},
              cascades=(("cpu_throttling", 2, 1.0),),
              description="Fan profile stuck low; inlet temperature climbs past the throttle point"),
    FaultSpec("cooling_failure", "thermal", "critical", {"temp_c": (96, 2.0), "fan_rpm": (11500, 300)},
              mode="ramp", ramp_ticks=6, cascades=(("cpu_throttling", 3, 1.0),),
              description="CRAC unit lost; fans at max but ambient rises across the cooling zone"),
    FaultSpec("fan_failure", "hardware", "medium", {"fan_rpm": (4000, 150)},
              cascades=(("thermal", 3, 1.0),),
              description="One chassis fan dead; remaining fans cannot hold temperature under load"),
    FaultSpec("cpu_throttling", "thermal", "medium", {"cpu_mhz": (1200, 100), "p99_latency_ms": (60, 8)},
              derived=True, description="Package throttled by firmware because of temperature"),
    FaultSpec("service_down", "software", "medium", {"service_up": (0, 0)},
              description="Workload service exited and did not restart"),
    FaultSpec("nic_errors", "network", "medium", {"nic_crc_per_min": (900, 80)},
              description="CRC errors on the NIC (bad optic or cable)"),
    FaultSpec("ecc_correctable", "hardware", "medium", {"ecc_ce_per_h": (600, 60)},
              description="Correctable ECC error storm on one DIMM"),
    FaultSpec("ecc_uncorrectable", "hardware", "high", {"ecc_ue": (1, 0)},
              description="Uncorrectable ECC error; next one panics the kernel"),
    FaultSpec("disk_failing", "hardware", "high", {"smart_realloc": (250, 20), "disk_latency_ms": (15, 3)},
              description="SMART reallocated sector count climbing; disk is dying"),
    FaultSpec("psu_failure", "power", "medium", {"psu_ok": (1, 0)},
              description="One of two PSUs lost input or failed"),
    FaultSpec("memory_leak", "software", "medium", {"mem_used_pct": (97, 1.0)}, mode="ramp", ramp_ticks=12,
              cascades=(("oom_kills", 12, 1.0),),
              description="Process leaks memory; RSS grows a few percent per tick until the OOM killer fires"),
    FaultSpec("oom_kills", "software", "high", {"oom_kills_per_h": (6, 2)},
              cascades=(("service_down", 2, 1.0),),
              description="Kernel OOM killer active; the workload will be killed soon"),
    FaultSpec("kernel_soft_lockup", "software", "high",
              {"soft_lockups_per_h": (4, 1), "load_1m": (40, 5), "p99_latency_ms": (300, 40)},
              description="CPU stuck in kernel for >20s; host is effectively hung"),
    FaultSpec("ntp_drift", "time", "medium", {"ntp_offset_ms": (2500, 100)}, mode="ramp", ramp_ticks=10,
              description="Clock drifting away from NTP; TLS and consensus break at a few seconds"),
    FaultSpec("raid_degraded", "hardware", "medium", {"raid_degraded": (1, 0), "disk_latency_ms": (6, 1)},
              description="RAID member dropped; array degraded, no redundancy"),
    FaultSpec("bmc_unreachable", "hardware", "medium", {"bmc_reachable": (0, 0)}, hides="bmc",
              description="BMC not responding to IPMI; no out-of-band sensors or power control"),
    FaultSpec("disk_latency", "hardware", "medium", {"disk_latency_ms": (45, 8), "p99_latency_ms": (80, 10)},
              description="Disk latency spike without SMART errors (firmware, queue depth, bad sectors)"),
    FaultSpec("packet_loss", "network", "medium", {"packet_loss_pct": (8, 2)},
              description="Persistent packet loss on the host link"),
    FaultSpec("uplink_loss", "network", "critical", {"packet_loss_pct": (45, 10), "link_flaps_per_h": (4, 1)},
              description="Rack uplink degraded (ToR failure); heavy loss on every host in the rack"),
    FaultSpec("link_flap", "network", "medium", {"link_flaps_per_h": (12, 3), "packet_loss_pct": (3, 1)},
              mode="intermittent", duty=0.5, period=4,
              description="NIC link bouncing up and down"),
    FaultSpec("firmware_mismatch", "hardware", "low", {"fw_mismatch": (1, 0)},
              description="BIOS/BMC firmware differs from the fleet baseline"),
    FaultSpec("cert_expiry", "security", "medium", {"cert_days_left": (0, 0)}, mode="ramp", ramp_ticks=10,
              description="Host TLS certificate approaching expiry"),
    FaultSpec("ssh_unreachable", "software", "high", {"ssh_reachable": (0, 0)}, hides="os",
              description="SSH not answering; in-band metrics unavailable"),
    FaultSpec("zombie_growth", "software", "low", {"zombie_procs": (800, 50)}, mode="ramp", ramp_ticks=15,
              description="Zombie processes accumulating (parent not reaping)"),
    FaultSpec("swap_exhaustion", "software", "medium", {"swap_used_pct": (96, 1.5)}, mode="ramp",
              ramp_ticks=10, cascades=(("oom_kills", 10, 1.0),),
              description="Swap filling up; host will start OOM-killing"),
    FaultSpec("inode_exhaustion", "software", "medium", {"inode_used_pct": (99.5, 0.2)}, mode="ramp",
              ramp_ticks=10, description="Inodes exhausted on the root filesystem"),
    FaultSpec("gpu_xid", "hardware", "high", {"gpu_xid_per_h": (5, 2)},
              description="GPU driver Xid errors (fallen off the bus, ECC, hangs)"),
    FaultSpec("nvme_wear", "hardware", "medium", {"nvme_wear_pct": (97, 1)},
              description="NVMe endurance nearly consumed"),
]}

FAULTS = tuple(FAULT_SPECS)

# Shared-infrastructure faults map to a per-host fault on every host underneath.
GROUP_FAULTS: dict[str, tuple[str, str]] = {  # group fault -> (scope, per-host fault)
    "tor_switch_failure": ("rack", "uplink_loss"),
    "pdu_failure": ("pdu", "psu_failure"),
    "cooling_failure": ("zone", "cooling_failure"),
}

BMC_METRICS = frozenset({"temp_c", "fan_rpm", "psu_ok"})
REACHABILITY = frozenset({"bmc_reachable", "ssh_reachable"})
PCT_METRICS = frozenset({"cpu_util", "mem_used_pct", "swap_used_pct", "inode_used_pct", "packet_loss_pct",
                         "nvme_wear_pct"})
COUNT_METRICS = frozenset({"ecc_ce_per_h", "ecc_ue", "smart_realloc", "nic_crc_per_min", "link_flaps_per_h",
                           "oom_kills_per_h", "zombie_procs", "gpu_xid_per_h", "soft_lockups_per_h"})

ROLE_LOAD = {"worker": 1.0, "cache": 0.9, "db-primary": 1.1, "db-replica": 0.8, "validator": 1.0,
             "gpu-worker": 1.3, "storage": 0.7, "ingress": 1.2}


def cascade_parents(child: str) -> list[str]:
    return [s.name for s in FAULT_SPECS.values() if any(c[0] == child for c in s.cascades)]


# --------------------------------------------------------------------------------------------
# Load pattern & active faults
# --------------------------------------------------------------------------------------------


@dataclass
class LoadPattern:
    """Diurnal load multiplier: 1 + amplitude * sin(2*pi*(tick+phase)/period), plus optional weekly dip."""

    period: int = 48
    amplitude: float = 0.0
    phase: int = 0
    weekly_period: int = 0  # 0 disables the weekly component
    weekly_amplitude: float = 0.0

    def factor(self, tick: int) -> float:
        f = 1.0
        if self.amplitude and self.period > 0:
            f += self.amplitude * math.sin(2 * math.pi * (tick + self.phase) / self.period)
        if self.weekly_amplitude and self.weekly_period > 0:
            f += self.weekly_amplitude * math.sin(2 * math.pi * tick / self.weekly_period)
        return max(0.05, f)


@dataclass
class ActiveFault:
    name: str
    since: int
    mode: str = "step"
    ramp_ticks: int = 0
    duty: float = 1.0
    period: int = 4
    group: str | None = None
    cascaded_from: str | None = None

    def intensity(self, tick: int) -> float:
        age = tick - self.since
        if age < 0:
            return 0.0
        if self.mode == "ramp" and self.ramp_ticks > 0:
            return min(1.0, age / self.ramp_ticks)
        if self.mode == "intermittent":
            return 1.0 if (age % max(1, self.period)) < self.duty * max(1, self.period) else 0.0
        return 1.0


@dataclass
class Host:
    id: str
    role: str
    rack: str
    drained: bool = False
    cordoned: bool = False
    throttled: bool = False
    ticketed: bool = False
    decommissioned: bool = False
    fan_profile: str = "auto"
    faults: dict[str, ActiveFault] = field(default_factory=dict)
    personality: dict[str, float] = field(default_factory=dict)
    cascade_done: set[tuple[str, str]] = field(default_factory=set)

    @property
    def active(self) -> bool:
        return not (self.drained or self.decommissioned)


# --------------------------------------------------------------------------------------------
# Fleet
# --------------------------------------------------------------------------------------------


class Fleet:
    def __init__(self, n: int = 30, seed: int = 0, topology: Topology | None = None,
                 load: LoadPattern | None = None, noise_scale: float = 1.0, hosts_per_rack: int = 10,
                 dcs: int = 1, rooms_per_dc: int = 1, roles: tuple[str, ...] | None = None):
        self.rng = random.Random(seed)
        self.seed = seed
        self.tick = 0
        self.load = load or LoadPattern()
        self.noise_scale = noise_scale
        self.topology = topology or Topology.build(n, dcs=dcs, rooms_per_dc=rooms_per_dc,
                                                   hosts_per_rack=hosts_per_rack)
        self.hosts: dict[str, Host] = {}
        self.fault_log: list[dict[str, Any]] = []  # (tick, host, fault, event) for evals
        self.last_sample: dict[str, dict[str, float]] = {}
        self.pending: list[tuple[int, str, tuple[str, ...]]] = []  # scheduled fault clears: (due tick, host, faults)
        self._place_roles(roles)

    # ---- construction -------------------------------------------------------------------------
    def _place_roles(self, roles: tuple[str, ...] | None) -> None:
        pool = list(roles or ROLES)
        weights = [ROLE_WEIGHTS.get(r, 1) for r in pool]
        protected_in_rack: set[str] = set()
        for hid in self.topology.hosts:
            rack = self.topology.host_rack[hid]
            role = self.rng.choices(pool, weights)[0]
            tries = 0
            while role in PROTECTED_ROLES and rack in protected_in_rack and tries < 5:
                role = self.rng.choices(pool, weights)[0]
                tries += 1
            if role in PROTECTED_ROLES and rack in protected_in_rack:
                role = "worker"
            if role in PROTECTED_ROLES:
                protected_in_rack.add(rack)
            self.hosts[hid] = Host(hid, role, rack, personality=self._personality())
        if len(self.hosts) >= 6:
            for need in ("db-primary", "validator"):
                if need in pool and not any(h.role == need for h in self.hosts.values()):
                    cand = [h for h in self.hosts.values() if h.role == "worker"]
                    if cand:
                        cand[-1].role = need

    def _personality(self) -> dict[str, float]:
        r = self.rng
        return {
            "temp": r.gauss(0, 2.0), "mem": r.gauss(0, 5.0), "nvme_wear": r.uniform(3, 40),
            "smart": float(r.randint(0, 4)), "inode": r.uniform(20, 45), "cert_days": r.uniform(120, 360),
            "zombies": float(r.randint(0, 2)), "fan": r.gauss(0, 150),
        }

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> Fleet:
        load_cfg = cfg.get("load") or {}
        load = LoadPattern(period=int(load_cfg.get("period", 48)), amplitude=float(load_cfg.get("amplitude", 0.0)),
                           phase=int(load_cfg.get("phase", 0)),
                           weekly_period=int(load_cfg.get("weekly_period", 0)),
                           weekly_amplitude=float(load_cfg.get("weekly_amplitude", 0.0)))
        return cls(n=int(cfg.get("hosts", 30)), seed=int(cfg.get("seed", 0)), load=load,
                   noise_scale=float(cfg.get("noise_scale", 1.0)), hosts_per_rack=int(cfg.get("hosts_per_rack", 10)),
                   dcs=int(cfg.get("dcs", 1)), rooms_per_dc=int(cfg.get("rooms_per_dc", 1)),
                   roles=tuple(cfg["roles"]) if cfg.get("roles") else None)

    # ---- fault injection ----------------------------------------------------------------------
    def inject(self, host_id: str, fault: str, mode: str | None = None, ramp_ticks: int | None = None,
               duty: float | None = None, period: int | None = None, group: str | None = None,
               cascaded_from: str | None = None) -> ActiveFault:
        if fault not in FAULT_SPECS:
            raise ValueError(f"unknown fault {fault!r}")
        spec = FAULT_SPECS[fault]
        af = ActiveFault(fault, self.tick, mode or spec.mode,
                         spec.ramp_ticks if ramp_ticks is None else ramp_ticks,
                         spec.duty if duty is None else duty, spec.period if period is None else period,
                         group, cascaded_from)
        self.hosts[host_id].faults[fault] = af
        self.fault_log.append({"tick": self.tick, "host": host_id, "fault": fault,
                               "event": "cascade" if cascaded_from else "inject", "group": group})
        return af

    def inject_group(self, group_fault: str, scope_id: str, **kw: Any) -> list[str]:
        """Inject a shared-infrastructure fault on every host under scope_id. Returns affected hosts."""
        if group_fault not in GROUP_FAULTS:
            raise ValueError(f"unknown group fault {group_fault!r}")
        scope, per_host = GROUP_FAULTS[group_fault]
        hosts = self.topology.scope_hosts(scope, scope_id)
        group = f"{group_fault}:{scope_id}:{self.tick}"
        for h in hosts:
            if not self.hosts[h].decommissioned:
                self.inject(h, per_host, group=group, **kw)
        self.fault_log.append({"tick": self.tick, "host": None, "fault": group_fault, "event": "inject_group",
                               "group": group, "scope": scope, "scope_id": scope_id, "hosts": hosts})
        return hosts

    def inject_rack(self, rack_id: str, group_fault: str = "tor_switch_failure", **kw: Any) -> list[str]:
        scope, _ = GROUP_FAULTS[group_fault]
        if scope == "rack":
            return self.inject_group(group_fault, rack_id, **kw)
        rack = self.topology.racks[rack_id]
        return self.inject_group(group_fault, rack.pdu if scope == "pdu" else rack.zone, **kw)

    def clear(self, host_id: str, fault: str) -> None:
        host = self.hosts[host_id]
        if host.faults.pop(fault, None) is not None:
            self.fault_log.append({"tick": self.tick, "host": host_id, "fault": fault, "event": "clear", "group": None})
        for child, af in list(host.faults.items()):
            if af.cascaded_from == fault and FAULT_SPECS[child].derived:
                self.clear(host_id, child)

    def clear_group(self, group: str) -> None:
        for h in self.hosts.values():
            for name, af in list(h.faults.items()):
                if af.group == group:
                    self.clear(h.id, name)

    def schedule_clear(self, host_id: str, faults: tuple[str, ...], delay_ticks: int) -> None:
        """Clear faults after `delay_ticks` (a runbook's duration): the fix lands when the work is done."""
        if delay_ticks <= 0:
            for f in faults:
                self.clear(host_id, f)
            return
        self.pending.append((self.tick + delay_ticks, host_id, tuple(faults)))

    def _apply_pending(self) -> None:
        due = [p for p in self.pending if p[0] <= self.tick]
        self.pending = [p for p in self.pending if p[0] > self.tick]
        for _, host_id, faults in due:
            for f in faults:
                self.clear(host_id, f)

    # ---- probes used by runbook preconditions / verifier ----------------------------------------
    def probe(self, host_id: str, what: str) -> bool:
        h = self.hosts[host_id]
        if what == "bmc_reachable":
            return "bmc_unreachable" not in h.faults
        if what == "ssh_reachable":
            return "ssh_unreachable" not in h.faults
        raise ValueError(f"unknown probe {what!r}")

    # ---- metrics -----------------------------------------------------------------------------
    def _noise(self, sd: float) -> float:
        return self.rng.gauss(0.0, sd * self.noise_scale) if sd > 0 else 0.0

    def load_factor(self, host: Host, tick: int | None = None) -> float:
        t = self.tick if tick is None else tick
        f = self.load.factor(t) * ROLE_LOAD.get(host.role, 1.0)
        if host.throttled:
            f *= 0.5
        if not host.active:
            f *= 0.1
        return f

    def healthy_metrics(self, host: Host) -> dict[str, float]:
        r, p = self.rng, host.personality
        load = self.load_factor(host)
        hs = 0.5 + load  # heteroscedastic noise multiplier
        m = {
            "temp_c": 60 + p["temp"] + 8 * (load - 1) + self._noise(2.0 * hs),
            "fan_rpm": 7800 + p["fan"] + 600 * (load - 1) + self._noise(220),
            "ecc_ce_per_h": float(r.randint(0, 3)), "ecc_ue": 0.0,
            "smart_realloc": p["smart"], "nic_crc_per_min": float(r.randint(0, 4)), "service_up": 1.0,
            "cpu_util": 45 * load + self._noise(6 * hs),
            "mem_used_pct": 55 + p["mem"] + 6 * (load - 1) + self._noise(2.0 * hs),
            "swap_used_pct": 2 + self._noise(1.0), "inode_used_pct": p["inode"] + self._noise(0.3),
            "disk_latency_ms": 2.0 * (0.8 + 0.4 * load) + self._noise(0.4 * hs),
            "packet_loss_pct": abs(self._noise(0.02)), "link_flaps_per_h": 1.0 if r.random() < 0.02 else 0.0,
            "cpu_mhz": 3000 + self._noise(30), "psu_ok": 2.0, "raid_degraded": 0.0,
            "bmc_reachable": 1.0, "ssh_reachable": 1.0, "ntp_offset_ms": self._noise(3.0),
            "oom_kills_per_h": 0.0, "zombie_procs": p["zombies"] + (1.0 if r.random() < 0.05 else 0.0),
            "gpu_xid_per_h": 0.0, "nvme_wear_pct": p["nvme_wear"],
            "cert_days_left": p["cert_days"] - self.tick / max(1, self.load.period),
            "fw_mismatch": 0.0, "soft_lockups_per_h": 0.0,
            "p99_latency_ms": 20 * (0.7 + 0.3 * load * load) + self._noise(3 * hs),
            "load_1m": 4 * load + self._noise(0.8 * hs),
        }
        if host.fan_profile == "max":
            m["fan_rpm"] = max(m["fan_rpm"], 11000 + self._noise(200))
            m["temp_c"] -= 6
        return m

    def metrics(self, host_id: str) -> dict[str, float]:
        host = self.hosts[host_id]
        m = self.healthy_metrics(host)
        hidden: set[str] = set()
        for af in host.faults.values():
            spec = FAULT_SPECS[af.name]
            k = af.intensity(self.tick)
            if k <= 0:
                continue
            for metric, (target, sd) in spec.metrics.items():
                base = m[metric]
                m[metric] = base + k * (target - base) + self._noise(sd * k)
            if spec.hides == "bmc":
                hidden |= BMC_METRICS
            elif spec.hides == "os":
                hidden |= set(m) - BMC_METRICS - REACHABILITY
        for metric in PCT_METRICS:
            m[metric] = min(100.0, max(0.0, m[metric]))
        for metric in COUNT_METRICS:
            m[metric] = max(0.0, round(m[metric]))
        for metric in ("disk_latency_ms", "p99_latency_ms", "load_1m", "fan_rpm", "cpu_mhz", "cert_days_left"):
            m[metric] = max(0.0, m[metric])
        for metric in hidden:
            m.pop(metric, None)
        return m

    def _advance_cascades(self) -> None:
        for hid in sorted(self.hosts):
            host = self.hosts[hid]
            for af in list(host.faults.values()):
                for child, delay, prob in FAULT_SPECS[af.name].cascades:
                    key = (af.name, child)
                    if key in host.cascade_done or child in host.faults:
                        continue
                    if self.tick - af.since >= delay and af.intensity(self.tick) >= 1.0 - 1e-9:
                        if self.rng.random() < prob:
                            self.inject(hid, child, cascaded_from=af.name, group=af.group)
                        host.cascade_done.add(key)

    def step(self) -> dict[str, dict[str, float]]:
        """Advance one tick. Returns metrics for active (non-drained) hosts; `last_sample` has all."""
        self.tick += 1
        self._apply_pending()
        self._advance_cascades()
        self.last_sample = {hid: self.metrics(hid) for hid in self.hosts}
        return {hid: m for hid, m in self.last_sample.items() if self.hosts[hid].active}

    # ---- fleet-level views -------------------------------------------------------------------
    def drained_fraction(self) -> float:
        return sum(not h.active for h in self.hosts.values()) / max(1, len(self.hosts))

    def role_counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for h in self.hosts.values():
            d = out.setdefault(h.role, {"total": 0, "active": 0, "drained": 0, "faulty": 0})
            d["total"] += 1
            d["active"] += h.active
            d["drained"] += not h.active
            d["faulty"] += bool(h.faults)
        return out

    def ground_truth(self) -> list[dict[str, Any]]:
        return [{"host": h.id, "fault": af.name, "since": af.since, "group": af.group,
                 "cascaded_from": af.cascaded_from, "mode": af.mode}
                for h in self.hosts.values() for af in h.faults.values()]

    def faulty_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.faults]
