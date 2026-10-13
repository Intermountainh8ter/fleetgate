"""Threshold detector with 2-tick hysteresis (cuts noise-triggered incidents)."""
from __future__ import annotations

from dataclasses import dataclass, field

RULES = {
    "thermal": lambda m: m["temp_c"] > 85 and m["fan_rpm"] < 5000,
    "service_down": lambda m: m["service_up"] < 0.5,
    "nic_errors": lambda m: m["nic_crc_per_min"] > 200,
    "ecc_correctable": lambda m: m["ecc_ce_per_h"] > 100,
    "ecc_uncorrectable": lambda m: m["ecc_ue"] >= 1,
    "disk_failing": lambda m: m["smart_realloc"] > 100,
}


@dataclass
class Incident:
    id: str
    host: str
    signal: str
    opened_tick: int
    evidence: dict[str, float] = field(default_factory=dict)


class Detector:
    def __init__(self, confirm_ticks: int = 2, clear_ticks: int = 3):
        self.confirm, self.clear = confirm_ticks, clear_ticks
        self.streak: dict[tuple[str, str], int] = {}
        self.quiet: dict[tuple[str, str], int] = {}
        self.open: dict[tuple[str, str], Incident] = {}

    def observe(self, tick: int, data: dict[str, dict[str, float]]) -> list[Incident]:
        new: list[Incident] = []
        for host, m in data.items():
            for sig, rule in RULES.items():
                key = (host, sig)
                if rule(m):
                    self.quiet[key] = 0
                    self.streak[key] = self.streak.get(key, 0) + 1
                    if self.streak[key] >= self.confirm and key not in self.open:
                        inc = Incident(f"inc-{host}-{sig}-{tick}", host, sig, tick, dict(m))
                        self.open[key] = inc
                        new.append(inc)
                else:
                    self.streak[key] = 0
                    if key in self.open:
                        self.quiet[key] = self.quiet.get(key, 0) + 1
                        if self.quiet[key] >= self.clear:
                            del self.open[key]
        # hosts that disappeared (drained) close their incidents
        for key in [k for k in self.open if k[0] not in data]:
            del self.open[key]
        return new
