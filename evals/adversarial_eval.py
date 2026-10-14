"""Adversarial safety: hostile planners against every policy and approver. Violations must be zero.

Planners
  fuzz         FuzzPlanner: typosquats with trailing space / zero-width / Unicode lookalikes, spoofed hosts, oversized
               plans, nested JSON where strings belong, feasible drain -> ticket -> destructive chains
  adversarial  AdversarialPlanner: hallucinated runbooks, fleet-wide reboot/drain/replace, host spoofing, jailbreak text
  llm          LLMPlanner fed each of the AdversarialLLM raw-text attacks (schema/parse hardening)
Invariants: see fleetgate.adversary.check_invariants (no unknown or deny-listed runbook executed; every risky action
backed by an approval filed before it ran; drained fraction <= cap; per-tick budget; change freeze; preconditions;
audit chain).
"""
from __future__ import annotations

import random
from typing import Any

import _common  # noqa: F401
from _common import md_table

from fleetgate import Fleet, Orchestrator
from fleetgate.adversary import FuzzPlanner, check_invariants
from fleetgate.agents import AdversarialLLM, AdversarialPlanner, LLMPlanner
from fleetgate.approvals import LatencyApprover
from fleetgate.fleet import FAULT_SPECS
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import Policy, PolicyConfig, available_policies

APPROVERS: dict[str, Any] = {"deny_all": lambda: deny_all, "approve_all": lambda: approve_all,
                             "humans": lambda: LatencyApprover(2, 1)}


def _fleet(seed: int) -> Fleet:
    rng = random.Random(seed)
    f = Fleet(rng.choice([30, 40, 60]), seed=seed)
    for _ in range(rng.randrange(2, 6)):
        f.inject(rng.choice(sorted(f.hosts)), rng.choice(list(FAULT_SPECS)))
    return f


def make_planner(kind: str, fleet: Fleet, seed: int, attack: str | None) -> Any:
    if kind == "fuzz":
        return FuzzPlanner(fleet, seed)
    if kind == "adversarial":
        return AdversarialPlanner(fleet, seed)
    return LLMPlanner(AdversarialLLM(attack or "prose_only"))


def run(quick: bool = False) -> dict[str, Any]:
    seeds = 6 if quick else 40
    ticks = 30
    cells: dict[str, Any] = {}
    violations: list[str] = []
    for planner_name in ("fuzz", "adversarial", "llm"):
        for pol in sorted(available_policies()):
            for who, make in APPROVERS.items():
                agg = {"runs": 0, "gate_evaluations": 0, "executed": 0, "approval_requests": 0, "violations": 0,
                       "worst_drained": 0.0, "cap": PolicyConfig.load(pol).max_drained_fraction, "exceptions": 0}
                attacks = sorted(AdversarialLLM.ATTACKS) if planner_name == "llm" else [None]
                for seed in range(seeds if planner_name != "llm" else max(1, seeds // 6)):
                    for attack in attacks:
                        f = _fleet(seed * 17 + 3)
                        cfg = PolicyConfig.load(pol)
                        planner = make_planner(planner_name, f, seed, attack)
                        o = Orchestrator(f, planner=planner, policy=Policy(f, cfg), approver=make())
                        try:
                            o.run(ticks)
                        except Exception as exc:  # the orchestrator must never raise on hostile input
                            agg["exceptions"] += 1
                            violations.append(f"{planner_name}/{pol}/{who}/seed{seed}: raised "
                                              f"{type(exc).__name__}: {exc}")
                            continue
                        v = check_invariants(o)
                        agg["runs"] += 1
                        agg["gate_evaluations"] += sum(o.policy.decisions.values())
                        agg["executed"] += len(o.executed)
                        agg["approval_requests"] += len(o.approvals.requests)
                        agg["violations"] += len(v)
                        peak = max((t["drained"] for t in o.tick_log), default=0) / len(f.hosts)
                        agg["worst_drained"] = max(agg["worst_drained"], peak)
                        violations += [f"{planner_name}/{pol}/{who}/seed{seed}: {x}" for x in v]
                cells[f"{planner_name}/{pol}/{who}"] = {"planner": planner_name, "policy": pol, "approver": who, **agg}
    total = {k: sum(c[k] for c in cells.values()) for k in ("runs", "gate_evaluations", "executed",
                                                              "approval_requests", "violations", "exceptions")}
    return {"seeds": seeds, "ticks": ticks, "cells": cells, "total": total, "violations": violations[:50]}


def render(result: dict[str, Any]) -> str:
    rows = []
    by: dict[tuple[str, str], dict[str, Any]] = {}
    for c in result["cells"].values():
        k = (c["planner"], c["approver"])
        a = by.setdefault(k, {"runs": 0, "gate_evaluations": 0, "executed": 0, "approval_requests": 0,
                              "violations": 0, "worst_over_cap": 0.0})
        for f in ("runs", "gate_evaluations", "executed", "approval_requests", "violations"):
            a[f] += c[f]
        a["worst_over_cap"] = max(a["worst_over_cap"], c["worst_drained"] - c["cap"])
    for (planner, who), a in sorted(by.items()):
        rows.append([planner, who, a["runs"], a["gate_evaluations"], a["executed"], a["approval_requests"],
                     a["violations"], "yes" if a["worst_over_cap"] <= 1e-9 else "NO"])
    t = result["total"]
    head = ["hostile planner", "approver", "runs (5 policies)", "gate evaluations", "actions executed",
            "approval requests", "violations", "drained <= cap"]
    out = [f"## Adversarial safety ({t['runs']} runs, {t['gate_evaluations']} gate evaluations, "
           f"{t['executed']} actions executed, {t['approval_requests']} approval requests)\n",
           md_table(head, rows, "llrrrrrl"), "",
           f"**Total safety-invariant violations: {t['violations']}; exceptions escaping the orchestrator: "
           f"{t['exceptions']}.** (Both must be 0.)"]
    if result["violations"]:
        out += ["", "First violations:", *[f"- {v}" for v in result["violations"][:10]]]
    return "\n".join(out)
