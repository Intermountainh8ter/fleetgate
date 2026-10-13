"""Policy gate between agent proposals and execution. Default posture: deny."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .fleet import Fleet
from .runbooks import CATALOG, Risk


class Decision(str, Enum):
    ALLOW = "ALLOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    DENY = "DENY"


@dataclass
class PolicyConfig:
    protected_roles: set[str] = field(default_factory=lambda: {"db-primary", "validator"})
    max_drained_fraction: float = 0.10
    cooldown_ticks: int = 5
    max_actions_per_tick: int = 3


@dataclass
class Verdict:
    decision: Decision
    reason: str


class Policy:
    def __init__(self, fleet: Fleet, config: PolicyConfig | None = None):
        self.fleet, self.cfg = fleet, config or PolicyConfig()
        self.recent: dict[tuple[str, str], int] = {}
        self.actions_this_tick: dict[int, int] = {}

    def evaluate(self, runbook_id: str, host_id: str) -> Verdict:
        rb = CATALOG.get(runbook_id)
        if rb is None:
            return Verdict(Decision.DENY, f"unknown runbook {runbook_id!r}")
        host = self.fleet.hosts.get(host_id)
        if host is None:
            return Verdict(Decision.DENY, f"unknown host {host_id!r}")
        if host.drained and runbook_id == "drain_host":
            return Verdict(Decision.DENY, "host already drained")
        t = self.fleet.tick
        last = self.recent.get((host_id, runbook_id))
        if last is not None and t - last < self.cfg.cooldown_ticks:
            return Verdict(Decision.DENY, f"cooldown: {runbook_id} on {host_id} ran {t - last} ticks ago")
        if self.actions_this_tick.get(t, 0) >= self.cfg.max_actions_per_tick:
            return Verdict(Decision.DENY, "per-tick action budget exhausted")
        if runbook_id == "drain_host":
            drained = sum(h.drained for h in self.fleet.hosts.values()) + 1
            if drained / len(self.fleet.hosts) > self.cfg.max_drained_fraction:
                return Verdict(Decision.DENY, "blast radius: would exceed max drained fraction")
        if rb.risk == Risk.DESTRUCTIVE:
            return Verdict(Decision.NEEDS_APPROVAL, f"{runbook_id} is destructive")
        if host.role in self.cfg.protected_roles:
            return Verdict(Decision.NEEDS_APPROVAL, f"{host.role} host is protected")
        return Verdict(Decision.ALLOW, "reversible action on unprotected host")

    def record(self, runbook_id: str, host_id: str) -> None:
        t = self.fleet.tick
        self.recent[(host_id, runbook_id)] = t
        self.actions_this_tick[t] = self.actions_this_tick.get(t, 0) + 1
