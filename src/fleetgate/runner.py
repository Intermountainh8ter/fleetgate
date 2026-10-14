"""Run a scenario end to end and score it against the simulator's ground truth."""
from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .agents import Planner
from .audit import AuditLog
from .detect import BaseDetector, MultiDetector, signal_metrics
from .fleet import FAULT_SPECS, Fleet
from .orchestrator import Orchestrator, deny_all
from .policy import Policy, PolicyConfig
from .scenarios import Scenario, apply_event


@dataclass
class FaultOutcome:
    host: str
    fault: str
    injected_tick: int
    group: str | None
    detected_tick: int | None = None
    incident_id: str | None = None
    exact_signal: bool = False
    status: str = "undetected"  # undetected | open | resolved | contained
    closed_tick: int | None = None

    @property
    def ttd(self) -> int | None:
        return None if self.detected_tick is None else self.detected_tick - self.injected_tick

    @property
    def ttr(self) -> int | None:
        return None if self.closed_tick is None or self.status != "resolved" else self.closed_tick - self.injected_tick

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "fault": self.fault, "injected_tick": self.injected_tick, "group": self.group,
                "detected_tick": self.detected_tick, "ttd": self.ttd, "incident_id": self.incident_id,
                "exact_signal": self.exact_signal, "status": self.status, "closed_tick": self.closed_tick,
                "ttr": self.ttr}


@dataclass
class RunResult:
    scenario: str
    policy: str
    orchestrator: Orchestrator
    outcomes: list[FaultOutcome] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fleet(self) -> Fleet:
        return self.orchestrator.fleet

    def summary(self) -> dict[str, Any]:
        s = self.orchestrator.summary()
        injected = list(self.outcomes)
        detected = [o for o in injected if o.detected_tick is not None]
        ttds = [o.ttd for o in detected if o.ttd is not None]
        ttrs = [o.ttr for o in injected if o.ttr is not None]
        injected_ids = {o.incident_id for o in detected if o.incident_id}
        cascade_only, spurious = 0, 0
        for rec in self.orchestrator.records.values():
            if rec.incident.id in injected_ids:
                continue
            kinds = {e["event"] for e in explaining_events(rec, self.fleet.fault_log)}
            if "inject" in kinds or "cascade" in kinds:
                cascade_only += 1  # a real anomaly (a follow-on fault or a second signal of an injected one)
            else:
                spurious += 1  # nothing in the ground truth explains this incident: a false positive
        s.update({"scenario": self.scenario, "policy": self.policy, "faults_injected": len(injected),
                  "faults_detected": len(detected),
                  "faults_resolved": sum(o.status == "resolved" for o in injected),
                  "faults_contained": sum(o.status == "contained" for o in injected),
                  "ttd_mean": round(sum(ttds) / len(ttds), 2) if ttds else None,
                  "ttr_mean": round(sum(ttrs) / len(ttrs), 2) if ttrs else None,
                  "follow_on_incidents": cascade_only, "spurious_incidents": spurious})
        s["max_drained_fraction"] = round(
            max((t["drained"] for t in self.orchestrator.tick_log), default=0) / max(1, s["hosts"]), 3)
        return s


def check_expectations(summary: dict[str, Any], expect: dict[str, Any] | None) -> list[str]:
    """Compare a run summary with a scenario's `min`/`max` bounds. Returns human-readable failures (empty = pass)."""
    failures: list[str] = []
    for key, bound in (expect or {}).get("min", {}).items():
        got = summary.get(key)
        if got is None or got < bound:
            failures.append(f"{key}: expected >= {bound}, got {got}")
    for key, bound in (expect or {}).get("max", {}).items():
        got = summary.get(key)
        if got is None or got > bound:
            failures.append(f"{key}: expected <= {bound}, got {got}")
    if summary.get("audit_ok") is False:
        failures.append("audit chain failed verification")
    return failures


def incident_signals(rec: Any) -> set[str]:
    if rec.is_group:
        return set(rec.incident.signal.split("+"))
    return {rec.incident.signal}


def signal_hits(signals: set[str], fault: str) -> bool:
    touched = set(FAULT_SPECS[fault].metrics)
    return fault in signals or any(set(signal_metrics(sig)) & touched for sig in signals)


def explaining_events(rec: Any, fault_log: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ground-truth fault events (injections and cascades) that make this incident a true positive."""
    sigs = incident_signals(rec)
    return [ev for ev in fault_log
            if ev["event"] in ("inject", "cascade") and ev["host"] in rec.hosts
            and ev["tick"] < rec.incident.opened_tick and signal_hits(sigs, ev["fault"])]


def run_scenario(scenario: Scenario, ticks: int | None = None, policy: PolicyConfig | str | None = None,
                 approver: Any = deny_all, planner: Planner | None = None,
                 detector: BaseDetector | MultiDetector | None = None, audit: AuditLog | None = None,
                 dry_run: bool = False, correlate: bool = True, llm: Any = None,
                 on_tick: Callable[[Orchestrator], None] | None = None, seed_offset: int = 0) -> RunResult:
    fleet_cfg = dict(scenario.fleet)
    fleet_cfg["seed"] = int(fleet_cfg.get("seed", 0)) + seed_offset
    fleet = Fleet.from_config(fleet_cfg)
    cfg = policy if isinstance(policy, PolicyConfig) else PolicyConfig.load(policy or scenario.policy)
    from .agents import RootCauseAgent, TriageAgent  # local import keeps module import light

    orch = Orchestrator(fleet, planner=planner, policy=Policy(fleet, cfg), approver=approver, audit=audit,
                        detector=detector, dry_run=dry_run, correlate=correlate, on_tick=on_tick,
                        triage=TriageAgent(fleet, llm, cfg.protected_roles) if llm else None,
                        root_cause=RootCauseAgent(fleet, llm) if llm else None)
    rng = random.Random(fleet_cfg["seed"] * 7919 + 17)
    result = RunResult(scenario.name, cfg.name, orch)
    horizon = ticks or scenario.ticks
    for _ in range(horizon):
        for ev in scenario.events_at(fleet.tick):  # events for tick t apply before the step producing t
            rec = apply_event(fleet, ev, rng)
            rec["tick"] = fleet.tick
            result.events.append(rec)
            orch.audit.append("scenario_event", tick=fleet.tick, **{k: v for k, v in rec.items() if k != "tick"})
        orch.tick()
    result.outcomes = score(orch)
    return result


def score(orch: Orchestrator) -> list[FaultOutcome]:
    """Match every injected (non-cascade) fault to the first incident that is evidence of it."""
    fleet = orch.fleet
    outcomes: list[FaultOutcome] = []
    recs = sorted(orch.records.values(), key=lambda r: r.incident.opened_tick)
    for ev in fleet.fault_log:
        if ev["event"] != "inject":
            continue
        host, fault = ev["host"], ev["fault"]
        o = FaultOutcome(host, fault, ev["tick"], ev["group"])
        for rec in recs:
            if rec.incident.opened_tick < ev["tick"] + 1 or host not in rec.hosts:
                continue
            if signal_hits(incident_signals(rec), fault):
                o.detected_tick, o.incident_id = rec.incident.opened_tick, rec.incident.id
                o.exact_signal = fault in incident_signals(rec)
                o.status = rec.status
                o.closed_tick = rec.closed_tick
                break
        if o.detected_tick is None:
            cleared = any(e["event"] == "clear" and e["host"] == host and e["fault"] == fault and e["tick"] > ev["tick"]
                          for e in fleet.fault_log)
            if cleared:
                o.status = "resolved"
        outcomes.append(o)
    return outcomes
