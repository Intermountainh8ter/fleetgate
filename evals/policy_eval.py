"""MTTR and containment: the 42 bundled scenarios replayed under every bundled policy and three kinds of human.

approvers
  instant   approve_all: every request is approved the tick it is filed (best case for MTTR)
  humans    LatencyApprover(base 2 ticks, +1 tick per extra approval): a plausible on-call response
  nobody    deny_all: no human ever answers 'yes' (shows what the gate does alone)

Metrics (per fault actually injected by the scenario):
  detected   an incident opened that is evidence of the fault
  resolved   the fault was gone (fixed) by the end of the run, never merely contained
  contained  the host was drained so the fault could do no further harm, but the fault is still there
  MTTR       ticks from injection to the fault being gone, over resolved faults only
  TTD        ticks from injection to the incident opening
Every run is also audited for safety-invariant violations; the total must be 0.
"""
from __future__ import annotations

from typing import Any

import _common  # noqa: F401
from _common import md_table

from fleetgate.adversary import check_invariants
from fleetgate.approvals import LatencyApprover
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import available_policies
from fleetgate.runner import run_scenario
from fleetgate.scenarios import load_scenarios

APPROVERS: dict[str, Any] = {"instant": lambda: approve_all, "humans": lambda: LatencyApprover(2, 1),
                             "nobody": lambda: deny_all}


def run(quick: bool = False) -> dict[str, Any]:
    scenarios = load_scenarios()
    names = sorted(scenarios)
    if quick:
        names = names[::3]
    cells: dict[str, Any] = {}
    for pol in sorted(available_policies()):
        for who, make in APPROVERS.items():
            tot = {"scenarios": 0, "injected": 0, "detected": 0, "resolved": 0, "contained": 0, "pages": 0,
                   "denied": 0, "executed": 0, "spurious": 0, "violations": 0}
            ttrs: list[float] = []
            ttds: list[float] = []
            peak = 0.0
            for n in names:
                r = run_scenario(scenarios[n], policy=pol, approver=make())
                s = r.summary()
                tot["scenarios"] += 1
                tot["injected"] += s["faults_injected"]
                tot["detected"] += s["faults_detected"]
                tot["resolved"] += s["faults_resolved"]
                tot["contained"] += s["faults_contained"]
                tot["pages"] += s["pages"]
                tot["denied"] += s["denied"]
                tot["executed"] += s["executed"]
                tot["spurious"] += s["spurious_incidents"]
                tot["violations"] += len(check_invariants(r.orchestrator))
                ttrs += [o.ttr for o in r.outcomes if o.ttr is not None]
                ttds += [o.ttd for o in r.outcomes if o.ttd is not None]
                peak = max(peak, s["max_drained_fraction"])
            inj = max(1, tot["injected"])
            cells[f"{pol}/{who}"] = {
                **tot, "policy": pol, "approver": who,
                "detect_rate": tot["detected"] / inj, "resolve_rate": tot["resolved"] / inj,
                "contain_rate": (tot["resolved"] + tot["contained"]) / inj,
                "mttr_mean": sum(ttrs) / len(ttrs) if ttrs else None,
                "mttr_median": sorted(ttrs)[len(ttrs) // 2] if ttrs else None,
                "ttd_mean": sum(ttds) / len(ttds) if ttds else None, "peak_drained": peak,
            }
    return {"scenarios": len(names), "cells": cells}


def render(result: dict[str, Any]) -> str:
    rows = []
    for c in result["cells"].values():
        rows.append([c["policy"], c["approver"], c["injected"], c["detect_rate"], c["resolve_rate"],
                     c["contain_rate"], c["mttr_mean"], c["mttr_median"], c["pages"], c["denied"],
                     c["peak_drained"], c["violations"]])
    head = ["policy", "approver", "faults", "detected", "resolved", "resolved+contained", "MTTR mean", "MTTR median",
            "pages", "denials", "peak drained", "violations"]
    n_pol = len({c["policy"] for c in result["cells"].values()})
    return (f"## MTTR and containment: {result['scenarios']} scenarios x {n_pol} policies x 3 approver models\n\n"
            "Rates are over all faults injected by the scenarios (one scenario may inject many). 'resolved' means the "
            "fault was fixed; 'resolved+contained' adds faults whose host was safely drained but still faulty. MTTR is "
            "over resolved faults only, in ticks. 'violations' = safety invariants broken (must be 0).\n\n"
            + md_table(head, rows, "ll" + "r" * (len(head) - 2)))
