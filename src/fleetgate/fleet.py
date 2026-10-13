"""Seeded bare-metal fleet simulator with injectable faults."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

FAULTS = ("thermal", "service_down", "nic_errors", "ecc_correctable", "ecc_uncorrectable", "disk_failing")
ROLES = ("worker", "worker", "worker", "cache", "db-primary", "validator")


@dataclass
class Host:
    id: str
    role: str
    rack: int
    drained: bool = False
    faults: dict[str, int] = field(default_factory=dict)  # fault -> tick injected
    ticketed: bool = False


class Fleet:
    def __init__(self, n: int = 30, seed: int = 0):
        self.rng = random.Random(seed)
        self.tick = 0
        self.hosts = {
            f"h{i:03d}": Host(f"h{i:03d}", self.rng.choice(ROLES), i // 10) for i in range(n)
        }

    def inject(self, host_id: str, fault: str) -> None:
        assert fault in FAULTS
        self.hosts[host_id].faults[fault] = self.tick

    def clear(self, host_id: str, fault: str) -> None:
        self.hosts[host_id].faults.pop(fault, None)

    def metrics(self, host_id: str) -> dict[str, float]:
        h, r = self.hosts[host_id], self.rng
        m = {
            "temp_c": r.gauss(62, 2.5), "fan_rpm": r.gauss(8000, 250),
            "ecc_ce_per_h": float(r.randint(0, 3)), "ecc_ue": 0.0,
            "smart_realloc": 0.0, "nic_crc_per_min": float(r.randint(0, 4)), "service_up": 1.0,
        }
        f = h.faults
        if "thermal" in f:
            m["temp_c"], m["fan_rpm"] = r.gauss(93, 2), r.gauss(2800, 200)
        if "service_down" in f:
            m["service_up"] = 0.0
        if "nic_errors" in f:
            m["nic_crc_per_min"] = r.gauss(900, 80)
        if "ecc_correctable" in f:
            m["ecc_ce_per_h"] = r.gauss(600, 60)
        if "ecc_uncorrectable" in f:
            m["ecc_ue"] = 1.0
        if "disk_failing" in f:
            m["smart_realloc"] = r.gauss(250, 20)
        return m

    def step(self) -> dict[str, dict[str, float]]:
        self.tick += 1
        return {hid: self.metrics(hid) for hid, h in self.hosts.items() if not h.drained}
