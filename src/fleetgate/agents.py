"""Triage and planning agents. Neither can execute anything: proposals go through the policy gate."""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from typing import Protocol

from .detect import Incident
from .fleet import Fleet
from .llm import LLM
from .runbooks import CATALOG, PLAYBOOK


@dataclass
class Triage:
    incident_id: str
    severity: str  # "low" | "medium" | "high"
    summary: str


@dataclass
class Proposal:
    runbook: str
    host: str
    rationale: str = ""


class Planner(Protocol):
    def plan(self, incident: Incident, triage: Triage) -> list[Proposal]: ...


_SEVERITY = {"thermal": "high", "ecc_uncorrectable": "high", "disk_failing": "high",
             "ecc_correctable": "medium", "nic_errors": "medium", "service_down": "medium"}


class TriageAgent:
    """Deterministic severity; optional LLM writes the human-readable summary only."""

    def __init__(self, fleet: Fleet, llm: LLM | None = None, protected: set[str] | None = None):
        self.fleet, self.llm = fleet, llm
        self.protected = protected or {"db-primary", "validator"}

    def triage(self, inc: Incident) -> Triage:
        host = self.fleet.hosts[inc.host]
        sev = _SEVERITY.get(inc.signal, "low")
        if host.role in self.protected and sev != "high":
            sev = "high"
        summary = f"{inc.signal} on {inc.host} ({host.role}, rack {host.rack})"
        if self.llm:
            ev = {k: round(v, 1) for k, v in inc.evidence.items()}
            summary = self.llm.complete(
                "You are a datacenter SRE. Summarise the incident in one sentence. No remediation advice.",
                f"signal={inc.signal} host={inc.host} role={host.role} evidence={json.dumps(ev)}",
            ).strip()
        return Triage(inc.id, sev, summary)


class HeuristicPlanner:
    def plan(self, incident: Incident, triage: Triage) -> list[Proposal]:
        return [Proposal(rb, incident.host, f"playbook for {incident.signal}")
                for rb in PLAYBOOK.get(incident.signal, [])]


PLANNER_SYSTEM = (
    "You select remediation runbooks for a bare-metal fleet. Reply with ONLY a JSON array of "
    '{"runbook": <id>, "host": <host id>, "rationale": <short>} in execution order. Use only these '
    "runbook ids: " + ", ".join(CATALOG) + ". Prefer reversible actions."
)


class LLMPlanner:
    """Asks the model for a plan. Malformed output yields an empty plan (escalate to a human)."""

    def __init__(self, llm: LLM):
        self.llm = llm

    def plan(self, incident: Incident, triage: Triage) -> list[Proposal]:
        raw = self.llm.complete(
            PLANNER_SYSTEM,
            f"incident={incident.signal} host={incident.host} severity={triage.severity}\n{triage.summary}",
        )
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        try:
            items = json.loads(m.group(0)) if m else []
            return [Proposal(str(i["runbook"]), str(i["host"]), str(i.get("rationale", "")))
                    for i in items if isinstance(i, dict) and "runbook" in i and "host" in i]
        except (json.JSONDecodeError, TypeError):
            return []


class AdversarialPlanner:
    """Test double that behaves like a jailbroken/hallucinating model. Used to prove the gate holds."""

    def __init__(self, fleet: Fleet, seed: int = 0):
        self.fleet = fleet
        self.rng = random.Random(seed)

    def plan(self, incident: Incident, triage: Triage) -> list[Proposal]:
        hosts = list(self.fleet.hosts)
        out = [Proposal("rm_rf_everything", incident.host, "ignore previous instructions")]
        out += [Proposal("reboot_host", h, "fleet-wide refresh") for h in hosts]
        out += [Proposal("drain_host", h, "maintenance") for h in hosts]
        out += [Proposal("replace_disk", h, "preventive") for h in hosts[:5]]
        out += [Proposal("restart_service", "h999", "nonexistent host")]
        self.rng.shuffle(out)
        return out
