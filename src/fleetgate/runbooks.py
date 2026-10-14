"""Closed catalogue of runbooks, loaded from a JSON spec and validated at import.

Agents can only *name* a runbook id; nothing else they emit is executable. A runbook is data:
a risk tier, a list of effect primitives (the only code that touches the fleet), preconditions
the gate probes before allowing it, verification probes the VerifierAgent re-reads afterwards,
an optional rollback partner, an estimated duration and a scope (host or whole rack).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from .detect import OPS
from .fleet import FAULT_SPECS, Fleet, Host
from .schema import SchemaError, check

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_SPEC = DATA_DIR / "runbooks.json"


class Tier(IntEnum):
    REVERSIBLE = 1
    DISRUPTIVE = 2
    DESTRUCTIVE = 3


Risk = Tier  # backwards-compatible alias

EFFECT_OPS = ("clear_fault", "clear_faults", "set_state", "clear_all_faults")
STATE_FIELDS = ("drained", "cordoned", "throttled", "ticketed", "decommissioned", "fan_profile", "role")
PRECONDITIONS = ("host_drained", "host_not_drained", "host_cordoned", "host_not_cordoned", "host_throttled",
                 "host_not_throttled", "bmc_reachable", "ssh_reachable", "ticket_open")

RUNBOOK_SCHEMA = {
    "type": "object",
    "required": ["id", "tier", "description", "effects", "preconditions", "verify", "duration_ticks"],
    "properties": {
        "id": {"type": "string", "pattern": r"^[a-z][a-z0-9_]{2,40}$"},
        "tier": {"enum": [t.name for t in Tier]},
        "description": {"type": "string", "minLength": 5, "maxLength": 200},
        "effects": {"type": "array", "minItems": 1, "items": {
            "type": "object", "required": ["op"],
            "properties": {"op": {"enum": list(EFFECT_OPS)}, "fault": {"type": "string"},
                           "faults": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                           "field": {"enum": list(STATE_FIELDS)}, "value": {}},
            "additionalProperties": False}},
        "preconditions": {"type": "array", "items": {"type": "string"}},
        "verify": {"type": "array", "items": {
            "type": "object",
            "properties": {"metric": {"type": "string"}, "op": {"enum": list(OPS)}, "value": {"type": "number"},
                           "state": {"enum": list(STATE_FIELDS)}, "equals": {}},
            "additionalProperties": False}},
        "rollback": {"type": ["string", "null"]},
        "duration_ticks": {"type": "integer", "minimum": 0, "maximum": 1000},
        "scope": {"enum": ["host", "rack"]},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}
SPEC_SCHEMA = {
    "type": "object",
    "required": ["version", "runbooks", "playbooks"],
    "properties": {
        "version": {"type": "integer", "minimum": 1},
        "runbooks": {"type": "array", "minItems": 1, "items": RUNBOOK_SCHEMA},
        "playbooks": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
        "group_playbooks": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
    },
    "additionalProperties": False,
}


@dataclass
class ApplyResult:
    runbook: str
    host: str
    hosts: list[str]
    changes: list[str]
    dry_run: bool = False


@dataclass(frozen=True)
class Runbook:
    id: str
    tier: Tier
    description: str
    effects: tuple[dict[str, Any], ...]
    preconditions: tuple[str, ...] = ()
    verify: tuple[dict[str, Any], ...] = ()
    rollback: str | None = None
    duration_ticks: int = 1
    scope: str = "host"
    tags: tuple[str, ...] = ()

    @property
    def risk(self) -> Tier:  # backwards-compatible name
        return self.tier

    @property
    def drains(self) -> bool:
        return any(e["op"] == "set_state" and e.get("field") in ("drained", "decommissioned") and e.get("value")
                   for e in self.effects)

    @property
    def cleared_faults(self) -> tuple[str, ...]:
        out: list[str] = []
        for e in self.effects:
            if e["op"] == "clear_fault":
                out.append(e["fault"])
            elif e["op"] == "clear_faults":
                out.extend(e["faults"])
            elif e["op"] == "clear_all_faults":
                out.extend(FAULT_SPECS)
        return tuple(dict.fromkeys(out))

    # ---- preconditions -----------------------------------------------------------------------
    def failed_preconditions(self, fleet: Fleet, host_id: str) -> list[str]:
        host = fleet.hosts.get(host_id)
        if host is None:
            return ["host_known"]
        failed: list[str] = []
        if host.decommissioned:
            failed.append("host_not_decommissioned")
        for pre in self.preconditions:
            if not _precondition_holds(pre, fleet, host):
                failed.append(pre)
        return failed

    # ---- execution ---------------------------------------------------------------------------
    def target_hosts(self, fleet: Fleet, host_id: str) -> list[str]:
        if self.scope == "rack":
            rack = fleet.hosts[host_id].rack
            return [h for h in fleet.topology.hosts_in_rack(rack) if not fleet.hosts[h].decommissioned]
        return [host_id]

    def apply(self, fleet: Fleet, host_id: str, dry_run: bool = False) -> ApplyResult:
        """State changes (drain, cordon, ticket) land immediately; fault clears land after `duration_ticks`."""
        hosts = self.target_hosts(fleet, host_id)
        changes: list[str] = []
        for h in hosts:
            host = fleet.hosts[h]
            for e in self.effects:
                changes.extend(_apply_effect(e, fleet, host, dry_run, self.duration_ticks))
        return ApplyResult(self.id, host_id, hosts, changes, dry_run)

    # ---- verification ------------------------------------------------------------------------
    def verify_probes(self, fleet: Fleet, host_id: str, metrics: dict[str, float] | None) -> list[str]:
        """Return the list of failed probes ([] means verified). Metrics are the latest sample."""
        host = fleet.hosts[host_id]
        failed: list[str] = []
        for p in self.verify:
            if "state" in p:
                if getattr(host, p["state"]) != p["equals"]:
                    failed.append(f"state {p['state']} != {p['equals']!r}")
            else:
                x = (metrics or {}).get(p["metric"])
                if x is None:
                    failed.append(f"metric {p['metric']} unavailable")
                elif not OPS[p["op"]](x, p["value"]):
                    failed.append(f"{p['metric']}={x:.3g} not {p['op']} {p['value']}")
        return failed

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "tier": self.tier.name, "description": self.description,
                "effects": list(self.effects), "preconditions": list(self.preconditions),
                "verify": list(self.verify), "rollback": self.rollback, "duration_ticks": self.duration_ticks,
                "scope": self.scope, "tags": list(self.tags)}


def _precondition_holds(pre: str, fleet: Fleet, host: Host) -> bool:
    if pre.startswith("role:"):
        return host.role == pre.split(":", 1)[1]
    return {
        "host_drained": host.drained, "host_not_drained": not host.drained,
        "host_cordoned": host.cordoned, "host_not_cordoned": not host.cordoned,
        "host_throttled": host.throttled, "host_not_throttled": not host.throttled,
        "bmc_reachable": fleet.probe(host.id, "bmc_reachable"),
        "ssh_reachable": fleet.probe(host.id, "ssh_reachable"),
        "ticket_open": host.ticketed,
    }[pre]


def _apply_effect(e: dict[str, Any], fleet: Fleet, host: Host, dry_run: bool, delay: int = 0) -> list[str]:
    op = e["op"]
    if op == "clear_fault":
        faults = [e["fault"]]
    elif op == "clear_faults":
        faults = list(e["faults"])
    elif op == "clear_all_faults":
        faults = list(host.faults)
    elif op == "set_state":
        before = getattr(host, e["field"])
        if before == e["value"]:
            return []
        if not dry_run:
            setattr(host, e["field"], e["value"])
        return [f"{host.id}.{e['field']}: {before!r} -> {e['value']!r}"]
    else:  # pragma: no cover - schema forbids
        raise ValueError(op)
    present = [f for f in faults if f in host.faults]
    if not dry_run and present:
        fleet.schedule_clear(host.id, tuple(present), delay)
    verb = "cleared" if delay <= 0 else f"clearing in {delay} ticks:"
    return [f"{host.id}: {verb} {f}" for f in present]


# --------------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------------


@dataclass
class RunbookRegistry:
    runbooks: dict[str, Runbook]
    playbooks: dict[str, list[str]]
    group_playbooks: dict[str, list[str]] = field(default_factory=dict)
    version: int = 1
    source: str = ""

    @classmethod
    def from_dict(cls, spec: dict[str, Any], source: str = "<dict>") -> RunbookRegistry:
        check(spec, SPEC_SCHEMA, f"runbook spec {source}")
        runbooks: dict[str, Runbook] = {}
        for r in spec["runbooks"]:
            if r["id"] in runbooks:
                raise SchemaError(f"runbook spec {source}: duplicate runbook id {r['id']!r}")
            for pre in r["preconditions"]:
                if pre not in PRECONDITIONS and not pre.startswith("role:"):
                    raise SchemaError(f"runbook {r['id']!r}: unknown precondition {pre!r}")
            for e in r["effects"]:
                _check_effect(r["id"], e)
            for p in r["verify"]:
                if ("state" in p) == ("metric" in p):
                    raise SchemaError(f"runbook {r['id']!r}: probe needs exactly one of state/metric")
                if "metric" in p and ("op" not in p or "value" not in p):
                    raise SchemaError(f"runbook {r['id']!r}: metric probe needs op and value")
                if "state" in p and "equals" not in p:
                    raise SchemaError(f"runbook {r['id']!r}: state probe needs equals")
            runbooks[r["id"]] = Runbook(
                r["id"], Tier[r["tier"]], r["description"], tuple(r["effects"]), tuple(r["preconditions"]),
                tuple(r["verify"]), r.get("rollback"), r["duration_ticks"], r.get("scope", "host"),
                tuple(r.get("tags", [])))
        for rb in runbooks.values():
            if rb.rollback is not None and rb.rollback not in runbooks:
                raise SchemaError(f"runbook {rb.id!r}: rollback {rb.rollback!r} is not a runbook")
            if rb.rollback is not None and runbooks[rb.rollback].tier > rb.tier:
                raise SchemaError(f"runbook {rb.id!r}: rollback {rb.rollback!r} is riskier than the action")
        for fault, steps in spec["playbooks"].items():
            if fault not in FAULT_SPECS:
                raise SchemaError(f"playbook for unknown fault {fault!r}")
            for s in steps:
                if s not in runbooks:
                    raise SchemaError(f"playbook {fault!r}: unknown runbook {s!r}")
        for hyp, steps in spec.get("group_playbooks", {}).items():
            for s in steps:
                if s not in runbooks:
                    raise SchemaError(f"group playbook {hyp!r}: unknown runbook {s!r}")
        return cls(runbooks, {k: list(v) for k, v in spec["playbooks"].items()},
                   {k: list(v) for k, v in spec.get("group_playbooks", {}).items()}, spec["version"], source)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_SPEC) -> RunbookRegistry:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh), str(path))

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "runbooks": [r.to_dict() for r in self.runbooks.values()],
                "playbooks": self.playbooks, "group_playbooks": self.group_playbooks}

    def by_tier(self, tier: Tier) -> list[Runbook]:
        return [r for r in self.runbooks.values() if r.tier == tier]

    def rollback_pairs(self) -> list[tuple[str, str]]:
        return [(r.id, r.rollback) for r in self.runbooks.values() if r.rollback]


def _check_effect(rid: str, e: dict[str, Any]) -> None:
    op = e["op"]
    if op == "clear_fault":
        if e.get("fault") not in FAULT_SPECS:
            raise SchemaError(f"runbook {rid!r}: clear_fault needs a known fault, got {e.get('fault')!r}")
    elif op == "clear_faults":
        bad = [f for f in e.get("faults", []) if f not in FAULT_SPECS]
        if bad or "faults" not in e:
            raise SchemaError(f"runbook {rid!r}: clear_faults has unknown faults {bad}")
    elif op == "set_state":
        if "field" not in e or "value" not in e:
            raise SchemaError(f"runbook {rid!r}: set_state needs field and value")
        if e["field"] in ("drained", "cordoned", "throttled", "ticketed", "decommissioned") \
                and not isinstance(e["value"], bool):
            raise SchemaError(f"runbook {rid!r}: {e['field']} must be boolean")
        if e["field"] == "fan_profile" and e["value"] not in ("auto", "max"):
            raise SchemaError(f"runbook {rid!r}: fan_profile must be auto|max")
        if e["field"] == "role" and not isinstance(e["value"], str):
            raise SchemaError(f"runbook {rid!r}: role must be a string")


REGISTRY: RunbookRegistry = RunbookRegistry.load()
CATALOG: dict[str, Runbook] = REGISTRY.runbooks
PLAYBOOK: dict[str, list[str]] = REGISTRY.playbooks
GROUP_PLAYBOOK: dict[str, list[str]] = REGISTRY.group_playbooks
