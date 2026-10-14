"""Scenario DSL: JSON/dict documents that describe a fleet and a timeline of fault events.

A scenario is plain data so it can be committed, diffed and generated. Example::

    {
      "name": "memory_leak_ramp",
      "description": "Slow leak on a worker, OOM after ~12 ticks",
      "fleet": {"hosts": 30, "seed": 7, "load": {"period": 48, "amplitude": 0.3}},
      "ticks": 40,
      "events": [
        {"tick": 3, "type": "inject", "host": {"role": "worker", "nth": 0}, "fault": "memory_leak"}
      ],
      "policy": "default",
      "tags": ["software", "ramp"]
    }

Event types: inject, inject_rack, inject_zone, inject_pdu, inject_random, clear, clear_all, set_load.
Host selectors: "h003" | {"role": "worker", "nth": 0} | "random" | {"random": true, "roles": [...]}.
Rack/zone/pdu selectors: explicit id | {"index": k} | "random".
Events with tick t are applied immediately before the step that produces tick t.
"""
from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .fleet import FAULT_SPECS, GROUP_FAULTS, Fleet
from .schema import check

_SELECTOR = {"type": ["string", "object"]}
EVENT_SCHEMA = {
    "type": "object",
    "required": ["tick", "type"],
    "properties": {
        "tick": {"type": "integer", "minimum": 0},
        "type": {"enum": ["inject", "inject_rack", "inject_zone", "inject_pdu", "inject_random", "clear",
                          "clear_all", "set_load"]},
        "host": _SELECTOR, "rack": _SELECTOR, "zone": _SELECTOR, "pdu": _SELECTOR,
        "fault": {"type": "string"},
        "faults": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "mode": {"enum": ["step", "ramp", "intermittent"]},
        "ramp_ticks": {"type": "integer", "minimum": 0},
        "duty": {"type": "number", "minimum": 0, "maximum": 1},
        "period": {"type": "integer", "minimum": 1},
        "count": {"type": "integer", "minimum": 1},
        "roles": {"type": "array", "items": {"type": "string"}},
        "amplitude": {"type": "number", "minimum": 0, "maximum": 1},
        "period_ticks": {"type": "integer", "minimum": 1},
        "note": {"type": "string"},
    },
    "additionalProperties": False,
}
SCENARIO_SCHEMA = {
    "type": "object",
    "required": ["name", "fleet", "ticks", "events"],
    "properties": {
        "name": {"type": "string", "pattern": r"^[a-z0-9_]+$", "maxLength": 64},
        "description": {"type": "string", "maxLength": 500},
        "fleet": {
            "type": "object",
            "properties": {
                "hosts": {"type": "integer", "minimum": 1, "maximum": 5000},
                "seed": {"type": "integer", "minimum": 0},
                "hosts_per_rack": {"type": "integer", "minimum": 1},
                "dcs": {"type": "integer", "minimum": 1},
                "rooms_per_dc": {"type": "integer", "minimum": 1},
                "noise_scale": {"type": "number", "minimum": 0},
                "roles": {"type": "array", "items": {"type": "string"}},
                "load": {"type": "object", "properties": {
                    "period": {"type": "integer", "minimum": 1}, "amplitude": {"type": "number", "minimum": 0},
                    "phase": {"type": "integer"}, "weekly_period": {"type": "integer", "minimum": 0},
                    "weekly_amplitude": {"type": "number", "minimum": 0}}, "additionalProperties": False},
            },
            "additionalProperties": False,
        },
        "ticks": {"type": "integer", "minimum": 1, "maximum": 100000},
        "events": {"type": "array", "items": EVENT_SCHEMA},
        "policy": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "expect": {"type": "object"},
    },
    "additionalProperties": False,
}


@dataclass
class Scenario:
    name: str
    fleet: dict[str, Any]
    ticks: int
    events: list[dict[str, Any]]
    description: str = ""
    policy: str = "default"
    tags: list[str] = field(default_factory=list)
    expect: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Scenario:
        check(d, SCENARIO_SCHEMA, f"scenario {d.get('name', '?')!r}")
        for ev in d["events"]:
            _check_event(ev, d["name"])
        return cls(name=d["name"], fleet=dict(d["fleet"]), ticks=int(d["ticks"]), events=list(d["events"]),
                   description=d.get("description", ""), policy=d.get("policy", "default"),
                   tags=list(d.get("tags", [])), expect=dict(d.get("expect", {})))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "description": self.description, "fleet": self.fleet,
                               "ticks": self.ticks, "events": self.events, "policy": self.policy, "tags": self.tags}
        if self.expect:
            out["expect"] = self.expect
        return out

    def build_fleet(self) -> Fleet:
        return Fleet.from_config(self.fleet)

    def events_at(self, tick: int) -> list[dict[str, Any]]:
        return [e for e in self.events if e["tick"] == tick]

    @property
    def faults(self) -> list[str]:
        out: list[str] = []
        for e in self.events:
            for f in [e.get("fault")] + list(e.get("faults", [])):
                if f and f not in out:
                    out.append(f)
        return out


def _check_event(ev: dict[str, Any], scen: str) -> None:
    t = ev["type"]
    if t == "inject":
        if "host" not in ev or "fault" not in ev:
            raise ValueError(f"scenario {scen!r}: inject needs host and fault")
        if ev["fault"] not in FAULT_SPECS:
            raise ValueError(f"scenario {scen!r}: unknown fault {ev['fault']!r}")
    elif t in ("inject_rack", "inject_zone", "inject_pdu"):
        key = t.split("_")[1]
        if key not in ev:
            raise ValueError(f"scenario {scen!r}: {t} needs {key!r}")
        if ev.get("fault", "tor_switch_failure") not in GROUP_FAULTS:
            raise ValueError(f"scenario {scen!r}: unknown group fault {ev.get('fault')!r}")
    elif t == "inject_random":
        bad = [f for f in ev.get("faults", []) if f not in FAULT_SPECS]
        if bad:
            raise ValueError(f"scenario {scen!r}: unknown faults {bad}")
    elif t == "clear":
        if "host" not in ev or "fault" not in ev:
            raise ValueError(f"scenario {scen!r}: clear needs host and fault")


# --------------------------------------------------------------------------------------------
# Event application
# --------------------------------------------------------------------------------------------


def resolve_host(fleet: Fleet, sel: Any, rng: random.Random) -> str:
    if isinstance(sel, str):
        if sel == "random":
            return rng.choice(sorted(fleet.hosts))
        if sel not in fleet.hosts:
            raise ValueError(f"unknown host {sel!r}")
        return sel
    roles = sel.get("roles") or ([sel["role"]] if "role" in sel else None)
    cands = [h.id for h in fleet.hosts.values() if (roles is None or h.role in roles) and not h.decommissioned]
    if not cands:
        raise ValueError(f"no host matches selector {sel!r}")
    if sel.get("random") or "nth" not in sel:
        return rng.choice(cands)
    return cands[sel["nth"] % len(cands)]


def resolve_scope(fleet: Fleet, kind: str, sel: Any, rng: random.Random) -> str:
    ids = {"rack": sorted(fleet.topology.racks), "zone": fleet.topology.zones, "pdu": fleet.topology.pdus}[kind]
    if isinstance(sel, str):
        if sel == "random":
            return rng.choice(ids)
        if sel not in ids:
            raise ValueError(f"unknown {kind} {sel!r}")
        return sel
    return ids[sel.get("index", 0) % len(ids)]


def apply_event(fleet: Fleet, ev: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """Apply one event to the fleet. Returns a record describing what happened (for the audit log)."""
    t = ev["type"]
    kw = {k: ev[k] for k in ("mode", "ramp_ticks", "duty", "period") if k in ev}
    if t == "inject":
        host = resolve_host(fleet, ev["host"], rng)
        fleet.inject(host, ev["fault"], **kw)
        return {"type": t, "host": host, "fault": ev["fault"]}
    if t in ("inject_rack", "inject_zone", "inject_pdu"):
        kind = t.split("_")[1]
        fault = ev.get("fault", {"rack": "tor_switch_failure", "zone": "cooling_failure", "pdu": "pdu_failure"}[kind])
        scope_id = resolve_scope(fleet, kind, ev[kind], rng)
        if kind == "rack":
            hosts = fleet.inject_rack(scope_id, fault, **kw)
        else:
            hosts = fleet.inject_group(fault, scope_id, **kw)
        return {"type": t, "scope": kind, "scope_id": scope_id, "fault": fault, "hosts": hosts}
    if t == "inject_random":
        faults = ev.get("faults") or list(FAULT_SPECS)
        roles = ev.get("roles")
        cands = [h.id for h in fleet.hosts.values() if (roles is None or h.role in roles) and not h.decommissioned]
        picked = []
        for _ in range(ev.get("count", 1)):
            if not cands:
                break
            host = rng.choice(cands)
            fault = rng.choice(faults)
            if fault not in fleet.hosts[host].faults:
                fleet.inject(host, fault, **kw)
                picked.append({"host": host, "fault": fault})
        return {"type": t, "injected": picked}
    if t == "clear":
        host = resolve_host(fleet, ev["host"], rng)
        fleet.clear(host, ev["fault"])
        return {"type": t, "host": host, "fault": ev["fault"]}
    if t == "clear_all":
        for h in fleet.hosts.values():
            for f in list(h.faults):
                fleet.clear(h.id, f)
        return {"type": t}
    if t == "set_load":
        if "amplitude" in ev:
            fleet.load.amplitude = float(ev["amplitude"])
        if "period_ticks" in ev:
            fleet.load.period = int(ev["period_ticks"])
        return {"type": t, "amplitude": fleet.load.amplitude, "period": fleet.load.period}
    raise ValueError(f"unknown event type {t!r}")


# --------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------


def scenario_dir(explicit: str | Path | None = None) -> Path:
    """Resolve the scenario directory: argument > $FLEETGATE_SCENARIO_DIR > <repo>/scenarios > ./scenarios."""
    if explicit:
        return Path(explicit)
    env = os.environ.get("FLEETGATE_SCENARIO_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "scenarios"
        if cand.is_dir() and any(cand.glob("*.json")):
            return cand
    return Path.cwd() / "scenarios"


def load_scenario(path: str | Path) -> Scenario:
    with open(path, encoding="utf-8") as fh:
        return Scenario.from_dict(json.load(fh))


def load_scenarios(directory: str | Path | None = None) -> dict[str, Scenario]:
    d = scenario_dir(directory)
    out: dict[str, Scenario] = {}
    for p in sorted(d.glob("*.json")):
        s = load_scenario(p)
        if s.name in out:
            raise ValueError(f"duplicate scenario name {s.name!r} in {p}")
        out[s.name] = s
    return out


def get_scenario(name: str, directory: str | Path | None = None) -> Scenario:
    p = Path(name)
    if p.suffix == ".json" and p.exists():
        return load_scenario(p)
    scen = load_scenarios(directory)
    if name not in scen:
        raise KeyError(f"unknown scenario {name!r}; known: {', '.join(sorted(scen))}")
    return scen[name]
