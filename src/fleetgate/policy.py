"""Policy gate between agent proposals and execution. Default posture: deny.

The gate is deterministic: the same proposal against the same fleet state and policy history
always yields the same verdict, and every verdict carries a machine-readable `Reason` code.
Rules are declared in JSON (see `data/policies/`) and evaluated in a fixed order; the first rule
that fires wins. Approval never bypasses a DENY: approval is only requested for proposals that
have already passed every hard limit. Any exception while evaluating fails closed (DENY).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .fleet import Fleet
from .runbooks import CATALOG, DATA_DIR, Tier
from .schema import check

POLICY_DIR = DATA_DIR / "policies"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    DENY = "DENY"


class Reason(str, Enum):
    """Machine-readable reason codes. The prefix tells you the decision family."""

    UNKNOWN_RUNBOOK = "DENY_UNKNOWN_RUNBOOK"
    UNKNOWN_HOST = "DENY_UNKNOWN_HOST"
    DENY_LIST = "DENY_LISTED_RUNBOOK"
    FREEZE_WINDOW = "DENY_FREEZE_WINDOW"
    PRECONDITION_FAILED = "DENY_PRECONDITION_FAILED"
    COOLDOWN = "DENY_COOLDOWN"
    TICK_BUDGET = "DENY_TICK_BUDGET"
    RATE_LIMIT = "DENY_RATE_LIMIT"
    QUOTA_ROLE = "DENY_QUOTA_ROLE"
    QUOTA_DC = "DENY_QUOTA_DC"
    BLAST_RADIUS = "DENY_BLAST_RADIUS"
    ROLE_CAPACITY_FLOOR = "DENY_ROLE_CAPACITY_FLOOR"
    CANARY_PENDING = "DENY_CANARY_PENDING"
    CANARY_FAILED = "DENY_CANARY_FAILED"
    APPROVAL_TIMEOUT = "DENY_APPROVAL_TIMEOUT"
    APPROVAL_REJECTED = "DENY_APPROVAL_REJECTED"
    INTERNAL_ERROR = "DENY_INTERNAL_ERROR"
    DESTRUCTIVE_TIER = "APPROVAL_DESTRUCTIVE_TIER"
    DISRUPTIVE_TIER = "APPROVAL_DISRUPTIVE_TIER"
    PROTECTED_ROLE = "APPROVAL_PROTECTED_ROLE"
    MAINTENANCE_WINDOW = "ALLOW_MAINTENANCE_WINDOW"
    CANARY = "ALLOW_CANARY"
    REVERSIBLE = "ALLOW_REVERSIBLE"

    @property
    def decision(self) -> Decision:
        return Decision(self.value.split("_", 1)[0].replace("APPROVAL", "NEEDS_APPROVAL"))


Pool = tuple[int, tuple[str, ...]]  # (approvals needed, roles allowed to give them)


@dataclass(frozen=True)
class ApprovalRequirement:
    """What a NEEDS_APPROVAL verdict asks for.

    `pools` lists independent N-of-M requirements (the tier's pool, plus the protected-role pool when the action
    touches a protected host). Every pool must be filled by *distinct* approvers, so a request that is both
    destructive and protected cannot be satisfied by the weaker of the two groups. `required` is the total number
    of approvals and `roles` the union of eligible roles in priority order (for display and approvers).
    """

    required: int
    roles: tuple[str, ...]
    code: Reason
    pools: tuple[Pool, ...] = ()

    def __post_init__(self) -> None:
        if not self.pools:
            object.__setattr__(self, "pools", ((self.required, self.roles),))

    @classmethod
    def from_pools(cls, pools: list[Pool], code: Reason) -> ApprovalRequirement:
        roles = tuple(dict.fromkeys(r for _, rs in pools for r in rs))
        return cls(sum(n for n, _ in pools), roles, code, tuple(pools))

    def satisfied_by(self, approvers: dict[str, str]) -> bool:
        """`approvers` maps distinct approver name -> role. True if every pool slot can get its own approver."""
        slots = [roles for n, roles in self.pools for _ in range(n)]
        owner: dict[str, int] = {}  # approver -> slot index it currently fills

        def place(slot: int, seen: set[str]) -> bool:
            for name, role in approvers.items():
                if role in slots[slot] and name not in seen:
                    seen.add(name)
                    if name not in owner or place(owner[name], seen):
                        owner[name] = slot
                        return True
            return False

        return all(place(i, set()) for i in range(len(slots)))

    def to_dict(self) -> dict[str, Any]:
        return {"required": self.required, "roles": list(self.roles), "code": self.code.value,
                "pools": [{"required": n, "roles": list(rs)} for n, rs in self.pools]}


@dataclass
class Verdict:
    decision: Decision
    reason: str
    code: Reason = Reason.INTERNAL_ERROR
    requirement: ApprovalRequirement | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision.value, "code": self.code.value, "reason": self.reason,
                "requirement": self.requirement.to_dict() if self.requirement else None}


# --------------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------------

_WINDOW = {"type": "object", "required": ["start", "end"],
           "properties": {"start": {"type": "integer", "minimum": 0}, "end": {"type": "integer", "minimum": 0},
                          "repeat_every": {"type": "integer", "minimum": 1}, "label": {"type": "string"},
                          "allow_tiers": {"type": "array", "items": {"enum": [t.name for t in Tier]}},
                          "dcs": {"type": ["array", "null"], "items": {"type": "string"}}},
           "additionalProperties": False}
_APPROVAL = {"type": "object", "required": ["required", "roles"],
             "properties": {"required": {"type": "integer", "minimum": 1, "maximum": 10},
                            "roles": {"type": "array", "minItems": 1, "items": {"type": "string"},
                                      "uniqueItems": True}},
             "additionalProperties": False}
POLICY_SCHEMA = {
    "type": "object",
    "required": ["name"],
    "properties": {
        "version": {"type": "integer", "minimum": 1},
        "name": {"type": "string", "pattern": r"^[a-z][a-z0-9_-]*$"},
        "description": {"type": "string"},
        "protected_roles": {"type": "array", "items": {"type": "string"}},
        "max_drained_fraction": {"type": "number", "minimum": 0, "maximum": 1},
        "cooldown_ticks": {"type": "integer", "minimum": 0},
        "max_actions_per_tick": {"type": "integer", "minimum": 0},
        "deny_list": {"type": "array", "items": {"type": "string"}},
        "freeze_windows": {"type": "array", "items": _WINDOW},
        "maintenance_windows": {"type": "array", "items": _WINDOW},
        "quotas": {"type": "object", "properties": {
            "window_ticks": {"type": "integer", "minimum": 1},
            "per_role": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
            "per_dc": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}},
            "additionalProperties": False},
        "approvals": {"type": "object", "properties": {"DESTRUCTIVE": _APPROVAL, "DISRUPTIVE": _APPROVAL,
                                                       "protected": _APPROVAL}, "additionalProperties": False},
        "escalation": {"type": "object", "properties": {
            "page_after_ticks": {"type": "integer", "minimum": 1},
            "expire_after_ticks": {"type": "integer", "minimum": 1}},
            "additionalProperties": False},
        "rate_limits": {"type": "object", "additionalProperties": {
            "type": "object", "required": ["max", "window_ticks"],
            "properties": {"max": {"type": "integer", "minimum": 0}, "window_ticks": {"type": "integer", "minimum": 1}},
            "additionalProperties": False}},
        "canary": {"type": "object", "properties": {
            "enabled": {"type": "boolean"}, "fleet_fraction": {"type": "number", "minimum": 0, "maximum": 1},
            "window_ticks": {"type": "integer", "minimum": 1}, "canary_count": {"type": "integer", "minimum": 1}},
            "additionalProperties": False},
        "min_active_per_role": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    },
    "additionalProperties": False,
}


def _default_approvals() -> dict[str, dict[str, Any]]:
    return {"DESTRUCTIVE": {"required": 2, "roles": ["sre-lead", "dc-ops"]},
            "DISRUPTIVE": {"required": 1, "roles": ["sre", "sre-lead"]},
            "protected": {"required": 1, "roles": ["sre-lead", "db-owner"]}}


@dataclass
class PolicyConfig:
    name: str = "default"
    description: str = ""
    protected_roles: set[str] = field(default_factory=lambda: {"db-primary", "validator"})
    max_drained_fraction: float = 0.10
    cooldown_ticks: int = 5
    max_actions_per_tick: int = 3
    deny_list: set[str] = field(default_factory=lambda: {"decommission_host"})
    freeze_windows: list[dict[str, Any]] = field(default_factory=list)
    maintenance_windows: list[dict[str, Any]] = field(default_factory=list)
    quotas: dict[str, Any] = field(default_factory=lambda: {"window_ticks": 24, "per_role": {}, "per_dc": {}})
    approvals: dict[str, dict[str, Any]] = field(default_factory=_default_approvals)
    escalation: dict[str, int] = field(default_factory=lambda: {"page_after_ticks": 3, "expire_after_ticks": 12})
    rate_limits: dict[str, dict[str, int]] = field(default_factory=dict)
    canary: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "fleet_fraction": 0.05,
                                                            "window_ticks": 10, "canary_count": 1})
    min_active_per_role: dict[str, int] = field(default_factory=lambda: {"db-primary": 1, "validator": 1})

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyConfig:
        check(d, POLICY_SCHEMA, f"policy {d.get('name', '?')!r}")
        cfg = cls(name=d["name"], description=d.get("description", ""))
        for key in ("max_drained_fraction", "cooldown_ticks", "max_actions_per_tick", "freeze_windows",
                    "maintenance_windows", "rate_limits", "min_active_per_role"):
            if key in d:
                setattr(cfg, key, d[key])
        if "protected_roles" in d:
            cfg.protected_roles = set(d["protected_roles"])
        if "deny_list" in d:
            cfg.deny_list = set(d["deny_list"])
        if "quotas" in d:
            cfg.quotas = {**cfg.quotas, **d["quotas"]}
        if "approvals" in d:
            cfg.approvals = {**cfg.approvals, **d["approvals"]}
        if "escalation" in d:
            cfg.escalation = {**cfg.escalation, **d["escalation"]}
        if "canary" in d:
            cfg.canary = {**cfg.canary, **d["canary"]}
        for w in cfg.freeze_windows + cfg.maintenance_windows:
            if w["end"] <= w["start"]:
                raise ValueError(f"policy {cfg.name!r}: window {w} must have end > start")
        for tier in ("DESTRUCTIVE", "DISRUPTIVE", "protected"):
            a = cfg.approvals[tier]
            if a["required"] > len(a["roles"]):
                raise ValueError(f"policy {cfg.name!r}: {tier} approvals need {a['required']} of "
                                 f"{len(a['roles'])} roles")
        for tier in ("DESTRUCTIVE", "DISRUPTIVE"):  # a tier plus the protected pool must still be fillable
            combined = ApprovalRequirement.from_pools(
                [(cfg.approvals[t]["required"], tuple(cfg.approvals[t]["roles"])) for t in (tier, "protected")],
                Reason.PROTECTED_ROLE)
            if not combined.satisfied_by({r: r for r in combined.roles}):
                raise ValueError(f"policy {cfg.name!r}: {tier} + protected approvals can never be satisfied by "
                                 "distinct approvers; add roles or lower 'required'")
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "name": self.name, "description": self.description,
                "protected_roles": sorted(self.protected_roles), "max_drained_fraction": self.max_drained_fraction,
                "cooldown_ticks": self.cooldown_ticks, "max_actions_per_tick": self.max_actions_per_tick,
                "deny_list": sorted(self.deny_list), "freeze_windows": self.freeze_windows,
                "maintenance_windows": self.maintenance_windows, "quotas": self.quotas, "approvals": self.approvals,
                "escalation": self.escalation, "rate_limits": self.rate_limits, "canary": self.canary,
                "min_active_per_role": self.min_active_per_role}

    @classmethod
    def load(cls, name_or_path: str | Path = "default") -> PolicyConfig:
        p = Path(name_or_path)
        if not p.exists():
            p = POLICY_DIR / f"{name_or_path}.json"
        if not p.exists():
            raise FileNotFoundError(f"no policy {name_or_path!r}; bundled: {', '.join(available_policies())}")
        with open(p, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def available_policies() -> list[str]:
    return sorted(p.stem for p in POLICY_DIR.glob("*.json"))


def _in_window(w: dict[str, Any], tick: int) -> bool:
    start, end, rep = w["start"], w["end"], w.get("repeat_every")
    if rep:
        t = tick % rep
        return start <= t < end
    return start <= tick < end


# --------------------------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------------------------


@dataclass
class _Campaign:
    proposed: dict[str, int] = field(default_factory=dict)  # host -> last tick proposed
    canaries: list[str] = field(default_factory=list)
    verified: bool = False
    failed_tick: int | None = None


class Policy:
    def __init__(self, fleet: Fleet, config: PolicyConfig | None = None):
        self.fleet, self.cfg = fleet, config or PolicyConfig()
        self.recent: dict[tuple[str, str], int] = {}  # (host, runbook) -> tick last executed
        self.actions_this_tick: dict[int, int] = {}
        self.history: list[dict[str, Any]] = []  # executed actions: tick, runbook, host, role, dc
        self.campaigns: dict[str, _Campaign] = {}
        self.decisions: dict[str, int] = {}  # reason code -> count

    # ---- public API --------------------------------------------------------------------------
    def evaluate(self, runbook_id: str, host_id: str) -> Verdict:
        try:
            v = self._evaluate(runbook_id, host_id)
        except Exception as exc:  # fail closed
            v = Verdict(Decision.DENY, f"internal error: {type(exc).__name__}: {exc}", Reason.INTERNAL_ERROR)
        self.decisions[v.code.value] = self.decisions.get(v.code.value, 0) + 1
        return v

    def record(self, runbook_id: str, host_id: str, hosts: list[str] | None = None) -> None:
        """Record an executed action (call after execution so cooldown/quotas/rate limits apply)."""
        t = self.fleet.tick
        for h in hosts or [host_id]:
            self.recent[(h, runbook_id)] = t
        self.actions_this_tick[t] = self.actions_this_tick.get(t, 0) + 1
        host = self.fleet.hosts.get(host_id)
        self.history.append({"tick": t, "runbook": runbook_id, "host": host_id,
                             "role": host.role if host else None,
                             "dc": self.fleet.topology.dc_of(host_id) if host else None})
        camp = self.campaigns.get(runbook_id)
        if camp and self._campaign_active(runbook_id, camp) and not camp.verified \
                and len(camp.canaries) < int(self.cfg.canary.get("canary_count", 1)):
            camp.canaries.append(host_id)

    def report_verification(self, runbook_id: str, host_id: str, ok: bool) -> None:
        """VerifierAgent feedback: a canary that verified unlocks the campaign, a failed one freezes it."""
        camp = self.campaigns.get(runbook_id)
        if not camp or host_id not in camp.canaries:
            return
        if ok:
            camp.verified = True
        else:
            camp.failed_tick = self.fleet.tick

    # ---- rule chain --------------------------------------------------------------------------
    def _evaluate(self, runbook_id: str, host_id: str) -> Verdict:
        cfg, t = self.cfg, self.fleet.tick
        rb = CATALOG.get(runbook_id)
        if rb is None:
            return Verdict(Decision.DENY, f"unknown runbook {runbook_id!r}", Reason.UNKNOWN_RUNBOOK)
        host = self.fleet.hosts.get(host_id)
        if host is None:
            return Verdict(Decision.DENY, f"unknown host {host_id!r}", Reason.UNKNOWN_HOST)
        # Every well-formed proposal counts toward a campaign, so a planner cannot dodge canary-first
        # by having most of its fleet-wide plan fail a later check.
        self.campaigns.setdefault(runbook_id, _Campaign()).proposed[host_id] = t
        if runbook_id in cfg.deny_list:
            return Verdict(Decision.DENY, f"{runbook_id} is on the deny-list", Reason.DENY_LIST)
        dc = self.fleet.topology.dc_of(host_id)
        targets = rb.target_hosts(self.fleet, host_id)
        protected = any(self.fleet.hosts[h].role in cfg.protected_roles for h in targets)
        in_maintenance = self._maintenance_window(dc, t)
        for w in cfg.freeze_windows:
            if not _in_window(w, t) or rb.tier.name in w.get("allow_tiers", []):
                continue
            # A maintenance window re-opens DISRUPTIVE work on unprotected hosts inside a freeze; DESTRUCTIVE never.
            if rb.tier == Tier.DISRUPTIVE and in_maintenance is not None and not protected:
                continue
            return Verdict(Decision.DENY, f"change freeze {w.get('label', '')!r}: {rb.tier.name} not allowed",
                           Reason.FREEZE_WINDOW)
        failed = rb.failed_preconditions(self.fleet, host_id)
        if failed:
            return Verdict(Decision.DENY, f"preconditions failed: {', '.join(failed)}", Reason.PRECONDITION_FAILED)
        last = self.recent.get((host_id, runbook_id))
        if last is not None and t - last < cfg.cooldown_ticks:
            return Verdict(Decision.DENY, f"cooldown: {runbook_id} on {host_id} ran {t - last} ticks ago",
                           Reason.COOLDOWN)
        if self.actions_this_tick.get(t, 0) >= cfg.max_actions_per_tick:
            return Verdict(Decision.DENY, "per-tick action budget exhausted", Reason.TICK_BUDGET)
        rl = cfg.rate_limits.get(runbook_id)
        if rl is not None:
            n = sum(1 for h in self.history if h["runbook"] == runbook_id and t - h["tick"] < rl["window_ticks"])
            if n >= rl["max"]:
                return Verdict(Decision.DENY, f"rate limit: {runbook_id} ran {n}x in {rl['window_ticks']} ticks",
                               Reason.RATE_LIMIT)
        q = cfg.quotas
        window = int(q.get("window_ticks", 24))
        role_cap = q.get("per_role", {}).get(host.role)
        if role_cap is not None:
            n = sum(1 for h in self.history if h["role"] == host.role and t - h["tick"] < window)
            if n >= role_cap:
                return Verdict(Decision.DENY, f"quota: {n} actions on role {host.role} in {window} ticks",
                               Reason.QUOTA_ROLE)
        dc_cap = q.get("per_dc", {}).get(dc)
        if dc_cap is not None:
            n = sum(1 for h in self.history if h["dc"] == dc and t - h["tick"] < window)
            if n >= dc_cap:
                return Verdict(Decision.DENY, f"quota: {n} actions in {dc} in {window} ticks", Reason.QUOTA_DC)
        if rb.drains:
            targets = [h for h in targets if self.fleet.hosts[h].active]
            drained = sum(not h.active for h in self.fleet.hosts.values()) + len(targets)
            if drained / len(self.fleet.hosts) > cfg.max_drained_fraction + 1e-12:
                return Verdict(Decision.DENY, "blast radius: would exceed max drained fraction", Reason.BLAST_RADIUS)
            for role, floor in cfg.min_active_per_role.items():
                active = sum(1 for h in self.fleet.hosts.values() if h.role == role and h.active)
                leaving = sum(1 for h in targets if self.fleet.hosts[h].role == role)
                if leaving and active - leaving < floor:
                    return Verdict(Decision.DENY,
                                   f"capacity floor: would leave {active - leaving} active {role} (< {floor})",
                                   Reason.ROLE_CAPACITY_FLOOR)
        canary = self._canary_check(rb.id, host_id)
        if canary is not None:
            return canary
        req = self._requirement(rb, protected)
        if rb.tier == Tier.DESTRUCTIVE:
            return Verdict(Decision.NEEDS_APPROVAL, f"{runbook_id} is destructive", Reason.DESTRUCTIVE_TIER, req)
        if rb.tier == Tier.DISRUPTIVE:
            if in_maintenance is not None and not protected:
                return Verdict(Decision.ALLOW,
                               f"disruptive action inside maintenance window {in_maintenance.get('label', '')!r}",
                               Reason.MAINTENANCE_WINDOW)
            return Verdict(Decision.NEEDS_APPROVAL, f"{runbook_id} is disruptive", Reason.DISRUPTIVE_TIER, req)
        if protected:
            return Verdict(Decision.NEEDS_APPROVAL, f"{runbook_id} touches a protected-role host",
                           Reason.PROTECTED_ROLE, req)
        if self._is_canary_slot(rb.id, host_id):
            return Verdict(Decision.ALLOW, "canary execution for a fleet-wide campaign", Reason.CANARY)
        return Verdict(Decision.ALLOW, "reversible action on unprotected host", Reason.REVERSIBLE)

    def _maintenance_window(self, dc: str, tick: int) -> dict[str, Any] | None:
        for w in self.cfg.maintenance_windows:
            if _in_window(w, tick) and (w.get("dcs") is None or dc in w["dcs"]):
                return w
        return None

    def _requirement(self, rb: Any, protected: bool) -> ApprovalRequirement | None:
        parts: list[tuple[dict[str, Any], Reason]] = []
        if rb.tier == Tier.DESTRUCTIVE:
            parts.append((self.cfg.approvals["DESTRUCTIVE"], Reason.DESTRUCTIVE_TIER))
        elif rb.tier == Tier.DISRUPTIVE:
            parts.append((self.cfg.approvals["DISRUPTIVE"], Reason.DISRUPTIVE_TIER))
        if protected:
            parts.append((self.cfg.approvals["protected"], Reason.PROTECTED_ROLE))
        if not parts:
            return None
        return ApprovalRequirement.from_pools([(p["required"], tuple(p["roles"])) for p, _ in parts], parts[0][1])

    # ---- canary-first ------------------------------------------------------------------------
    def _campaign_threshold(self) -> int:
        frac = float(self.cfg.canary.get("fleet_fraction", 0.05))
        return max(2, math.ceil(frac * len(self.fleet.hosts)))

    def _campaign_active(self, runbook_id: str, camp: _Campaign) -> bool:
        if not self.cfg.canary.get("enabled", True):
            return False
        window = int(self.cfg.canary.get("window_ticks", 10))
        live = [h for h, tk in camp.proposed.items() if self.fleet.tick - tk < window]
        return len(live) >= self._campaign_threshold()

    def _canary_check(self, runbook_id: str, host_id: str) -> Verdict | None:
        if not self.cfg.canary.get("enabled", True):
            return None
        camp = self.campaigns.setdefault(runbook_id, _Campaign())
        if not self._campaign_active(runbook_id, camp):
            return None
        window = int(self.cfg.canary.get("window_ticks", 10))
        if camp.failed_tick is not None and self.fleet.tick - camp.failed_tick < window:
            return Verdict(Decision.DENY, f"canary for {runbook_id} failed verification; campaign frozen",
                           Reason.CANARY_FAILED)
        if camp.verified or host_id in camp.canaries:
            return None
        if len(camp.canaries) < int(self.cfg.canary.get("canary_count", 1)):
            return None  # this proposal becomes a canary when recorded
        return Verdict(Decision.DENY, f"canary-first: {runbook_id} is fleet-wide; waiting for canary verification",
                       Reason.CANARY_PENDING)

    def _is_canary_slot(self, runbook_id: str, host_id: str) -> bool:
        camp = self.campaigns.get(runbook_id)
        return bool(camp and self._campaign_active(runbook_id, camp) and not camp.verified
                    and host_id not in camp.canaries)

    # ---- introspection -----------------------------------------------------------------------
    def explain(self) -> list[str]:
        """Human-readable summary of the active rules (used by `fleetgate policy show`)."""
        c = self.cfg
        lines = [f"policy {c.name}: {c.description}".rstrip(": "),
                 f"protected roles: {', '.join(sorted(c.protected_roles)) or '-'}",
                 f"max drained fraction: {c.max_drained_fraction:.0%}; cooldown {c.cooldown_ticks} ticks; "
                 f"{c.max_actions_per_tick} actions/tick",
                 f"deny-list: {', '.join(sorted(c.deny_list)) or '-'}"]
        for tier, a in c.approvals.items():
            lines.append(f"approvals {tier}: {a['required']} of {', '.join(a['roles'])}")
        for w in c.freeze_windows:
            lines.append(f"freeze {w.get('label', '')!r}: ticks [{w['start']}, {w['end']}) "
                         f"allow {w.get('allow_tiers', [])}")
        for w in c.maintenance_windows:
            lines.append(f"maintenance {w.get('label', '')!r}: ticks [{w['start']}, {w['end']}) "
                         f"dcs {w.get('dcs') or 'all'}")
        if c.rate_limits:
            lines.append("rate limits: " + ", ".join(f"{k} {v['max']}/{v['window_ticks']}t"
                                                      for k, v in c.rate_limits.items()))
        q = c.quotas
        if q.get("per_role") or q.get("per_dc"):
            lines.append(f"quotas per {q.get('window_ticks')} ticks: roles {q.get('per_role', {})} "
                         f"dcs {q.get('per_dc', {})}")
        if c.canary.get("enabled", True):
            lines.append(f"canary-first: campaigns >= {c.canary.get('fleet_fraction', 0.05):.0%} of fleet need "
                         f"{c.canary.get('canary_count', 1)} verified canary")
        lines.append(f"escalation: page after {c.escalation['page_after_ticks']} ticks, expire after "
                     f"{c.escalation['expire_after_ticks']}")
        lines.append(f"capacity floors: {c.min_active_per_role}")
        return lines
