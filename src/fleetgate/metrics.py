"""Prometheus text-format export of a run (or of a replayed audit log)."""
from __future__ import annotations

from typing import Any

from .audit import ReplayState
from .orchestrator import Orchestrator


def _fmt_labels(labels: dict[str, Any]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{str(v).replace(chr(34), chr(39))}"' for k, v in labels.items()) + "}"


class MetricsRegistry:
    def __init__(self, prefix: str = "fleetgate"):
        self.prefix = prefix
        self.samples: list[tuple[str, str, str, dict[str, Any], float]] = []  # name, type, help, labels, value
        self._help: dict[str, tuple[str, str]] = {}

    def add(self, name: str, value: float, labels: dict[str, Any] | None = None, kind: str = "gauge",
            help_text: str = "") -> None:
        full = f"{self.prefix}_{name}"
        self._help.setdefault(full, (kind, help_text))
        self.samples.append((full, kind, help_text, labels or {}, float(value)))

    def render(self) -> str:
        lines: list[str] = []
        seen: set[str] = set()
        for name, kind, help_text, labels, value in self.samples:
            if name not in seen:
                seen.add(name)
                lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} {kind}")
            v = int(value) if float(value).is_integer() else value
            lines.append(f"{name}{_fmt_labels(labels)} {v}")
        return "\n".join(lines) + "\n"


def from_orchestrator(orch: Orchestrator) -> MetricsRegistry:
    m = MetricsRegistry()
    s = orch.summary()
    m.add("tick", s["ticks"], help_text="Current simulation tick")
    m.add("hosts_total", s["hosts"], help_text="Hosts in the fleet")
    m.add("hosts_drained", sum(not h.active for h in orch.fleet.hosts.values()), help_text="Hosts drained or decommissioned")
    m.add("hosts_faulty", len(orch.fleet.faulty_hosts()), help_text="Hosts with at least one active fault (ground truth)")
    for role, c in sorted(orch.fleet.role_counts().items()):
        m.add("role_hosts", c["total"], {"role": role, "state": "total"}, help_text="Hosts per role and state")
        m.add("role_hosts", c["active"], {"role": role, "state": "active"})
        m.add("role_hosts", c["drained"], {"role": role, "state": "drained"})
    for st in ("open", "resolved", "contained"):
        m.add("incidents", s[st], {"status": st}, help_text="Incidents by status")
    m.add("incidents_total", s["incidents"], kind="counter", help_text="Incidents opened")
    m.add("actions_executed_total", s["executed"], kind="counter", help_text="Runbook executions")
    rb_counts: dict[str, int] = {}
    for _, rb, _ in orch.executed:
        rb_counts[rb] = rb_counts.get(rb, 0) + 1
    for rb, n in sorted(rb_counts.items()):
        m.add("runbook_executions_total", n, {"runbook": rb}, kind="counter", help_text="Executions per runbook")
    for code, n in sorted(s["decisions"].items()):
        m.add("policy_decisions_total", n, {"code": code}, kind="counter", help_text="Policy verdicts by reason code")
    for st, n in s["approvals"].items():
        m.add("approvals", n, {"status": st}, help_text="Approval requests by status")
    m.add("pages_total", s["pages"], kind="counter", help_text="Pages sent to humans")
    m.add("verify_failures_total", s["verify_failures"], kind="counter", help_text="Runbook verifications that failed")
    m.add("rollbacks_total", s["rollbacks"], kind="counter", help_text="Rollback runbooks executed")
    if s["mttr_mean"] is not None:
        m.add("mttr_ticks_mean", s["mttr_mean"], help_text="Mean ticks from detection to resolution")
    m.add("audit_entries", s["audit_entries"], help_text="Audit log length")
    m.add("audit_chain_ok", 1 if s["audit_ok"] else 0, help_text="1 if the audit hash chain verifies")
    # fleet-wide metric averages (one series per metric, not per host)
    if orch.last_data:
        keys = sorted({k for m_ in orch.last_data.values() for k in m_})
        for k in keys:
            vals = [m_[k] for m_ in orch.last_data.values() if k in m_]
            if vals:
                m.add("fleet_metric_avg", sum(vals) / len(vals), {"metric": k}, help_text="Fleet-wide mean of a host metric")
                m.add("fleet_metric_max", max(vals), {"metric": k}, help_text="Fleet-wide max of a host metric")
    return m


def from_replay(state: ReplayState) -> MetricsRegistry:
    m = MetricsRegistry()
    m.add("tick", state.last_tick, help_text="Last tick seen in the audit log")
    by_status: dict[str, int] = {}
    for inc in state.incidents.values():
        by_status[inc["status"]] = by_status.get(inc["status"], 0) + 1
    for st, n in sorted(by_status.items()):
        m.add("incidents", n, {"status": st}, help_text="Incidents by status (replayed)")
    m.add("incidents_total", len(state.incidents), kind="counter", help_text="Incidents opened (replayed)")
    m.add("actions_executed_total", len(state.executed), kind="counter", help_text="Runbook executions (replayed)")
    for rb, n in sorted(state.runbook_counts.items()):
        m.add("runbook_executions_total", n, {"runbook": rb}, kind="counter", help_text="Executions per runbook (replayed)")
    for code, n in sorted(state.decisions.items()):
        m.add("policy_decisions_total", n, {"code": code}, kind="counter", help_text="Policy verdicts by reason code")
    m.add("hosts_drained", len(state.drained), help_text="Hosts drained according to the log")
    m.add("pages_total", len(state.pages), kind="counter", help_text="Pages (replayed)")
    m.add("audit_checkpoints", state.checkpoints, help_text="Merkle checkpoints in the log")
    return m
