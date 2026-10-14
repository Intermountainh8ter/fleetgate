"""Detectors: thresholds with hysteresis, EWMA z-score anomalies, and a diurnal-aware seasonal baseline.

All detectors share one hysteresis engine (`BaseDetector`): a (host, signal) pair must fire for
`confirm_ticks` consecutive ticks to open an incident and stay quiet for `clear_ticks` to close it.
Subclasses only implement `signals()`, which maps one host's metrics to the signals that fire now.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

OPS = {
    ">": lambda a, b: a > b, ">=": lambda a, b: a >= b, "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
    "abs>": lambda a, b: abs(a) > b, "abs<": lambda a, b: abs(a) < b, "==": lambda a, b: a == b,
}


@dataclass(frozen=True)
class Rule:
    signal: str
    conditions: tuple[tuple[str, str, float], ...]  # ANDed (metric, op, threshold)
    severity: str = "medium"

    @property
    def metrics(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(m for m, _, _ in self.conditions))

    def fires(self, m: dict[str, float], margin: float = 1.0) -> bool:
        """`margin` scales thresholds toward the healthy side (<1 = more sensitive, >1 = stricter)."""
        for metric, op, value in self.conditions:
            x = m.get(metric)
            if x is None:
                return False
            if margin != 1.0 and op in (">", ">=", "abs>"):
                value = value * margin
            elif margin != 1.0 and op in ("<", "<=", "abs<") and value > 0:
                value = value / margin
            if not OPS[op](x, value):
                return False
        return True


RULES: dict[str, Rule] = {r.signal: r for r in [
    Rule("thermal", (("temp_c", ">", 85), ("fan_rpm", "<", 5000)), "high"),
    Rule("cooling_failure", (("temp_c", ">", 85), ("fan_rpm", ">=", 5000)), "critical"),
    Rule("fan_failure", (("fan_rpm", "<", 5000), ("temp_c", "<=", 85)), "medium"),
    Rule("cpu_throttling", (("cpu_mhz", "<", 2000),), "medium"),
    Rule("service_down", (("service_up", "<", 0.5),), "medium"),
    Rule("nic_errors", (("nic_crc_per_min", ">", 200),), "medium"),
    Rule("ecc_correctable", (("ecc_ce_per_h", ">", 100),), "medium"),
    Rule("ecc_uncorrectable", (("ecc_ue", ">=", 1),), "high"),
    Rule("disk_failing", (("smart_realloc", ">", 100),), "high"),
    Rule("psu_failure", (("psu_ok", "<", 2),), "medium"),
    Rule("memory_leak", (("mem_used_pct", ">", 90),), "medium"),
    Rule("oom_kills", (("oom_kills_per_h", ">=", 1),), "high"),
    Rule("kernel_soft_lockup", (("soft_lockups_per_h", ">=", 1),), "high"),
    Rule("ntp_drift", (("ntp_offset_ms", "abs>", 500),), "medium"),
    Rule("raid_degraded", (("raid_degraded", ">=", 1),), "medium"),
    Rule("bmc_unreachable", (("bmc_reachable", "<", 1),), "medium"),
    Rule("disk_latency", (("disk_latency_ms", ">", 20),), "medium"),
    Rule("packet_loss", (("packet_loss_pct", ">", 2), ("packet_loss_pct", "<=", 20)), "medium"),
    Rule("uplink_loss", (("packet_loss_pct", ">", 20),), "critical"),
    Rule("link_flap", (("link_flaps_per_h", ">", 3),), "medium"),
    Rule("firmware_mismatch", (("fw_mismatch", ">=", 1),), "low"),
    Rule("cert_expiry", (("cert_days_left", "<", 7),), "medium"),
    Rule("ssh_unreachable", (("ssh_reachable", "<", 1),), "high"),
    Rule("zombie_growth", (("zombie_procs", ">", 200),), "low"),
    Rule("swap_exhaustion", (("swap_used_pct", ">", 80),), "medium"),
    Rule("inode_exhaustion", (("inode_used_pct", ">", 95),), "medium"),
    Rule("gpu_xid", (("gpu_xid_per_h", ">=", 1),), "high"),
    Rule("nvme_wear", (("nvme_wear_pct", ">", 90),), "medium"),
]}

# Direction in which a metric is "bad" for the statistical detectors: up | down | both.
DIRECTION: dict[str, str] = {
    "temp_c": "up", "fan_rpm": "both", "ecc_ce_per_h": "up", "ecc_ue": "up", "smart_realloc": "up",
    "nic_crc_per_min": "up", "service_up": "down", "cpu_util": "up", "mem_used_pct": "up", "swap_used_pct": "up",
    "inode_used_pct": "up", "disk_latency_ms": "up", "packet_loss_pct": "up", "link_flaps_per_h": "up",
    "cpu_mhz": "down", "psu_ok": "down", "raid_degraded": "up", "bmc_reachable": "down", "ssh_reachable": "down",
    "ntp_offset_ms": "both", "oom_kills_per_h": "up", "zombie_procs": "up", "gpu_xid_per_h": "up",
    "nvme_wear_pct": "up", "cert_days_left": "down", "fw_mismatch": "up", "soft_lockups_per_h": "up",
    "p99_latency_ms": "up", "load_1m": "up",
}
# Floor on the standard deviation used for z-scores so near-constant metrics do not explode.
STD_FLOOR: dict[str, float] = {
    "temp_c": 1.0, "fan_rpm": 150.0, "cpu_util": 3.0, "mem_used_pct": 1.5, "disk_latency_ms": 0.5,
    "p99_latency_ms": 2.0, "load_1m": 0.5, "cpu_mhz": 25.0, "ntp_offset_ms": 3.0, "inode_used_pct": 0.3,
    "swap_used_pct": 1.0, "packet_loss_pct": 0.05, "cert_days_left": 0.5, "nvme_wear_pct": 0.5,
    "ecc_ce_per_h": 1.5, "nic_crc_per_min": 1.5, "zombie_procs": 1.0, "smart_realloc": 1.0,
    # state / binary metrics: any change is meaningful, so a flip must score far above the usual 4-sigma threshold
    "service_up": 0.05, "psu_ok": 0.05, "raid_degraded": 0.05, "bmc_reachable": 0.05, "ssh_reachable": 0.05,
    "ecc_ue": 0.05, "fw_mismatch": 0.05, "soft_lockups_per_h": 0.1, "oom_kills_per_h": 0.1,
    "gpu_xid_per_h": 0.1, "link_flaps_per_h": 0.5,
}
DEFAULT_STD_FLOOR = 0.25


def signal_metrics(signal: str) -> tuple[str, ...]:
    """Metrics a signal is evidence about (used by detection evals to match signals to faults)."""
    if signal in RULES:
        return RULES[signal].metrics
    if ":" in signal:
        return (signal.split(":", 1)[1],)
    return ()


@dataclass
class Incident:
    id: str
    host: str
    signal: str
    opened_tick: int
    evidence: dict[str, float] = field(default_factory=dict)
    detector: str = "threshold"
    score: float = 0.0
    severity: str = "medium"


class BaseDetector:
    name = "base"

    def __init__(self, confirm_ticks: int = 2, clear_ticks: int = 3):
        self.confirm, self.clear = confirm_ticks, clear_ticks
        self.streak: dict[str, dict[str, int]] = {}  # host -> signal -> consecutive firing ticks
        self.quiet: dict[str, dict[str, int]] = {}  # host -> signal -> consecutive quiet ticks
        self.open: dict[tuple[str, str], Incident] = {}
        self.closed: list[tuple[int, Incident]] = []  # (closed tick, incident)

    def signals(self, host: str, m: dict[str, float], tick: int) -> dict[str, tuple[float, str]]:
        """Return {signal: (score, severity)} for signals firing on this host right now."""
        raise NotImplementedError

    def observe(self, tick: int, data: dict[str, dict[str, float]]) -> list[Incident]:
        new: list[Incident] = []
        for host, m in data.items():
            firing = self.signals(host, m, tick)
            streak = self.streak.setdefault(host, {})
            quiet = self.quiet.setdefault(host, {})
            for sig, (score, severity) in firing.items():
                quiet.pop(sig, None)
                streak[sig] = streak.get(sig, 0) + 1
                if streak[sig] >= self.confirm and (host, sig) not in self.open:
                    ev = {k: round(v, 3) for k, v in m.items() if isinstance(v, (int, float))}
                    inc = Incident(f"inc-{host}-{sig}-{tick}", host, sig, tick, ev, self.name, score, severity)
                    self.open[(host, sig)] = inc
                    new.append(inc)
            for sig in [s for s in streak if s not in firing]:
                del streak[sig]
                if (host, sig) in self.open:
                    quiet[sig] = 0
            for sig in [s for s in quiet if s not in firing and (host, s) in self.open]:
                quiet[sig] += 1
                if quiet[sig] >= self.clear:
                    self.closed.append((tick, self.open.pop((host, sig))))
                    del quiet[sig]
        for key in [k for k in self.open if k[0] not in data]:  # drained hosts close their incidents
            self.closed.append((tick, self.open.pop(key)))
        return new

    def open_signals(self, host: str) -> list[str]:
        return [sig for (h, sig) in self.open if h == host]


class ThresholdDetector(BaseDetector):
    """Static thresholds. `margin` < 1 makes every rule more sensitive (used by the sensitivity sweep)."""

    name = "threshold"

    def __init__(self, confirm_ticks: int = 2, clear_ticks: int = 3, rules: dict[str, Rule] | None = None,
                 margin: float = 1.0):
        super().__init__(confirm_ticks, clear_ticks)
        self.rules = rules or RULES
        self.margin = margin

    def signals(self, host: str, m: dict[str, float], tick: int) -> dict[str, tuple[float, str]]:
        return {sig: (1.0, r.severity) for sig, r in self.rules.items() if r.fires(m, self.margin)}


Detector = ThresholdDetector  # backwards-compatible name


class _Stat:
    __slots__ = ("mean", "var", "n")

    def __init__(self) -> None:
        self.mean, self.var, self.n = 0.0, 0.0, 0

    def update(self, x: float, alpha: float) -> None:
        if self.n == 0:
            self.mean, self.var = x, 0.0
        else:
            d = x - self.mean
            self.mean += alpha * d
            self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1

    def z(self, x: float, floor: float) -> float:
        return (x - self.mean) / max(math.sqrt(max(self.var, 0.0)), floor)

    def update_var(self, sq: float, alpha: float) -> None:
        """Track an EWMA of squared residuals in `var` (used for pooled seasonal variance)."""
        self.var = sq if self.n == 0 else self.var + alpha * (sq - self.var)
        self.n += 1


def _directional(z: float, metric: str) -> float:
    d = DIRECTION.get(metric, "up")
    if d == "up":
        return max(z, 0.0)
    if d == "down":
        return max(-z, 0.0)
    return abs(z)


class EWMADetector(BaseDetector):
    """Per-(host, metric) exponentially weighted mean/variance; fires on a directional z-score.

    The baseline is frozen while a metric is anomalous so a slow ramp is not absorbed into "normal".
    """

    name = "ewma"

    def __init__(self, alpha: float = 0.1, z_threshold: float = 4.0, warmup: int = 10, confirm_ticks: int = 2,
                 clear_ticks: int = 3, metrics: Iterable[str] | None = None):
        super().__init__(confirm_ticks, clear_ticks)
        self.alpha, self.z, self.warmup = alpha, z_threshold, warmup
        self.metrics = set(metrics) if metrics else None
        self.stats: dict[tuple[str, str], _Stat] = {}

    def signals(self, host: str, m: dict[str, float], tick: int) -> dict[str, tuple[float, str]]:
        out: dict[str, tuple[float, str]] = {}
        for metric, x in m.items():
            if self.metrics is not None and metric not in self.metrics:
                continue
            st = self.stats.setdefault((host, metric), _Stat())
            if st.n < self.warmup:
                st.update(x, self.alpha)
                continue
            z = _directional(st.z(x, STD_FLOOR.get(metric, DEFAULT_STD_FLOOR)), metric)
            if z > self.z:
                out[f"ewma:{metric}"] = (z, "high" if z > 2 * self.z else "medium")
            else:
                st.update(x, self.alpha)
        return out


class SeasonalDetector(BaseDetector):
    """Diurnal-aware baseline: one EWMA mean per (host, metric, phase-of-day bin).

    Each bin is visited only once per cycle, so its own variance estimate is very noisy early on. The scale of a
    z-score therefore shrinks the bin's variance toward a pooled residual variance for that (host, metric),
    which is estimated from every bin and converges quickly (`shrinkage` pseudo-observations of the pool).
    """

    name = "seasonal"

    def __init__(self, period: int = 48, bins: int = 8, alpha: float = 0.3, z_threshold: float = 4.0,
                 min_obs: int = 3, confirm_ticks: int = 2, clear_ticks: int = 3,
                 metrics: Iterable[str] | None = None, shrinkage: float = 4.0, pool_alpha: float = 0.05):
        super().__init__(confirm_ticks, clear_ticks)
        self.period, self.bins, self.alpha, self.z, self.min_obs = period, bins, alpha, z_threshold, min_obs
        self.shrinkage, self.pool_alpha = shrinkage, pool_alpha
        self.metrics = set(metrics) if metrics else None
        self.stats: dict[tuple[str, str, int], _Stat] = {}
        self.pooled: dict[tuple[str, str], _Stat] = {}  # residual variance across all bins (mean field unused)

    def phase_bin(self, tick: int) -> int:
        return (tick % self.period) * self.bins // self.period

    def _scale(self, st: _Stat, pool: _Stat, floor: float) -> float:
        var = (st.n * st.var + self.shrinkage * pool.var) / (st.n + self.shrinkage) if pool.n else st.var
        return max(math.sqrt(max(var, 0.0)), floor)

    def signals(self, host: str, m: dict[str, float], tick: int) -> dict[str, tuple[float, str]]:
        out: dict[str, tuple[float, str]] = {}
        b = self.phase_bin(tick)
        for metric, x in m.items():
            if self.metrics is not None and metric not in self.metrics:
                continue
            st = self.stats.setdefault((host, metric, b), _Stat())
            pool = self.pooled.setdefault((host, metric), _Stat())
            if st.n < self.min_obs:
                if st.n:
                    pool.update_var((x - st.mean) ** 2, self.pool_alpha)
                st.update(x, self.alpha)
                continue
            floor = STD_FLOOR.get(metric, DEFAULT_STD_FLOOR)
            z = _directional((x - st.mean) / self._scale(st, pool, floor), metric)
            if z > self.z:
                out[f"seasonal:{metric}"] = (z, "high" if z > 2 * self.z else "medium")
            else:
                pool.update_var((x - st.mean) ** 2, self.pool_alpha)
                st.update(x, self.alpha)
        return out


class MultiDetector:
    """Runs several detectors and de-duplicates by (host, signal)."""

    name = "multi"

    def __init__(self, detectors: list[BaseDetector]):
        self.detectors = detectors

    @property
    def open(self) -> dict[tuple[str, str], Incident]:
        merged: dict[tuple[str, str], Incident] = {}
        for d in self.detectors:
            for k, v in d.open.items():
                merged.setdefault(k, v)
        return merged

    def observe(self, tick: int, data: dict[str, dict[str, float]]) -> list[Incident]:
        seen: set[tuple[str, str]] = set()
        out: list[Incident] = []
        for d in self.detectors:
            for inc in d.observe(tick, data):
                key = (inc.host, inc.signal)
                if key not in seen:
                    seen.add(key)
                    out.append(inc)
        return out

    def open_signals(self, host: str) -> list[str]:
        return sorted({s for d in self.detectors for s in d.open_signals(host)})


def summarize_evidence(inc: Incident, limit: int = 4) -> dict[str, Any]:
    keys = signal_metrics(inc.signal) or tuple(inc.evidence)[:limit]
    return {k: inc.evidence[k] for k in keys if k in inc.evidence}
