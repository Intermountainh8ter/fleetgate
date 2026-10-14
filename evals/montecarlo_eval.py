"""Monte Carlo policy sweep: how much MTTR does each safety knob cost, and what exposure does it buy?

Grid (36 policy configurations, all other settings as in `default`):
  drain cap            0.05 | 0.10 | 0.20   max fraction of the fleet drained at once (blast radius)
  destructive sign-offs 1 | 2 | 3           distinct approvers needed for a DESTRUCTIVE runbook
  actions per tick      1 | 3               per-tick change budget
  canary-first          off | on            fleet-wide campaigns must prove themselves on one host

Each configuration faces the same N seeded storms (40 hosts, 10 random faults over ticks 3-20, 70 ticks, a mix where
most faults need a drain so the blast-radius cap actually binds) with simulated
humans (LatencyApprover: first approval after 2 ticks, +1 tick per extra approval), so the comparison is paired.

Axes (all measured in the run, nothing assumed):
  censored MTTR   mean over injected faults of (ticks to fix), counting an unfixed fault as the ticks it was exposed
                  until the run ended: lower is better, and a policy cannot look fast by simply never fixing things
  peak drained    worst fraction of the fleet drained at any moment (capacity exposure): lower is safer
  sign-offs       mean human approvals behind each DISRUPTIVE/DESTRUCTIVE action actually executed: higher is safer
A configuration is on the Pareto front if no other is at least as good on all three axes and better on one.
"""
from __future__ import annotations

import itertools
import random
from typing import Any

import _common  # noqa: F401
from _common import md_table

from fleetgate import Fleet
from fleetgate.adversary import check_invariants
from fleetgate.approvals import LatencyApprover
from fleetgate.orchestrator import Orchestrator
from fleetgate.policy import Policy, PolicyConfig
from fleetgate.runbooks import CATALOG, Tier
from fleetgate.runner import score

CAPS = (0.05, 0.10, 0.20)
SIGNOFFS = (1, 2, 3)
BUDGETS = (1, 3)
CANARY = (False, True)
TICKS = 70
FLEET = 40
FAULTS_PER_RUN = 10
# Storm mix: most faults need a drain (so the blast-radius cap and approval queue are exercised), some are reversible
# restarts, some are slow ramps. Weights are a modelling choice, stated here so nothing is hidden.
STORM_MIX = (["disk_failing"] * 3 + ["ecc_uncorrectable"] * 2 + ["kernel_soft_lockup"] * 2 + ["gpu_xid", "nvme_wear",
             "ssh_unreachable", "firmware_mismatch", "disk_latency", "ecc_correctable"] +
             ["service_down"] * 3 + ["memory_leak", "nic_errors", "packet_loss", "thermal"])


def make_config(cap: float, signoffs: int, budget: int, canary: bool) -> PolicyConfig:
    d = PolicyConfig.load("default").to_dict()
    d["name"] = f"mc-cap{int(cap * 100)}-so{signoffs}-b{budget}-{'canary' if canary else 'nocanary'}"
    d["max_drained_fraction"] = cap
    d["max_actions_per_tick"] = budget
    d["approvals"]["DESTRUCTIVE"] = {"required": signoffs, "roles": ["sre-lead", "dc-ops", "change-manager"]}
    d["canary"] = {**d["canary"], "enabled": canary}
    d["quotas"] = {"window_ticks": 24, "per_role": {}, "per_dc": {}}
    return PolicyConfig.from_dict(d)


def storm(seed: int) -> Fleet:
    rng = random.Random(seed)
    f = Fleet(FLEET, seed=900 + seed)
    f.pending.clear()
    schedule = sorted((rng.randrange(3, 21), rng.choice(sorted(f.hosts)), rng.choice(STORM_MIX))
                      for _ in range(FAULTS_PER_RUN))
    f._mc_schedule = schedule  # type: ignore[attr-defined]  # applied tick by tick in run_one
    return f


def run_one(cfg: PolicyConfig, seed: int) -> dict[str, Any]:
    f = storm(seed)
    o = Orchestrator(f, policy=Policy(f, cfg), approver=LatencyApprover(2, 1))
    schedule = list(f._mc_schedule)  # type: ignore[attr-defined]
    for _ in range(TICKS):
        while schedule and schedule[0][0] <= f.tick + 1:
            _, host, fault = schedule.pop(0)
            if fault not in f.hosts[host].faults:
                f.inject(host, fault)
        o.tick()
    outcomes = score(o)
    times = []
    for oc in outcomes:
        times.append(oc.ttr if oc.ttr is not None else TICKS - oc.injected_tick)
    ttr = [oc.ttr for oc in outcomes if oc.ttr is not None]
    approved = {e["request_id"]: len(e["approvers"]) for e in o.audit.entries
                if e["kind"] == "approval_resolved" and e["status"] == "approved"}
    risky = [e for e in o.audit.entries if e["kind"] == "executed" and CATALOG[e["runbook"]].tier != Tier.REVERSIBLE]
    signoffs = [approved.get(e["request_id"], 0) for e in risky]
    return {"injected": len(outcomes), "resolved": len(ttr), "censored_mttr_sum": sum(times), "ttr": ttr,
            "peak_drained": max((t["drained"] for t in o.tick_log), default=0) / FLEET,
            "risky_actions": len(risky), "signoffs": signoffs, "pages": len(o.pages),
            "violations": len(check_invariants(o))}


def run(quick: bool = False) -> dict[str, Any]:
    seeds = 6 if quick else 8
    rows = []
    for cap, so, budget, canary in itertools.product(CAPS, SIGNOFFS, BUDGETS, CANARY):
        cfg = make_config(cap, so, budget, canary)
        runs = [run_one(cfg, s) for s in range(seeds)]
        inj = sum(r["injected"] for r in runs)
        ttr = [t for r in runs for t in r["ttr"]]
        so_all = [x for r in runs for x in r["signoffs"]]
        rows.append({
            "config": cfg.name, "drain_cap": cap, "destructive_signoffs": so, "actions_per_tick": budget,
            "canary": canary, "runs": len(runs), "faults": inj,
            "censored_mttr": sum(r["censored_mttr_sum"] for r in runs) / max(1, inj),
            "mttr_resolved": sum(ttr) / len(ttr) if ttr else None,
            "resolve_rate": sum(r["resolved"] for r in runs) / max(1, inj),
            "peak_drained": sum(r["peak_drained"] for r in runs) / len(runs),
            "signoffs_per_risky_action": sum(so_all) / len(so_all) if so_all else None,
            "risky_actions": sum(r["risky_actions"] for r in runs), "pages": sum(r["pages"] for r in runs),
            "violations": sum(r["violations"] for r in runs),
        })
    mark_pareto(rows)
    return {"seeds": seeds, "runs": sum(r["runs"] for r in rows), "configs": len(rows), "rows": rows,
            "violations": sum(r["violations"] for r in rows), "marginals": marginals(rows)}


def _key(r: dict[str, Any]) -> tuple[float, float, float]:
    so = r["signoffs_per_risky_action"] or 0.0
    return (r["censored_mttr"], r["peak_drained"], -so)


def mark_pareto(rows: list[dict[str, Any]]) -> None:
    for r in rows:
        r["pareto"] = not any(all(a <= b + 1e-12 for a, b in zip(_key(o), _key(r)))
                              and any(a < b - 1e-12 for a, b in zip(_key(o), _key(r))) for o in rows if o is not r)


def marginals(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for knob in ("drain_cap", "destructive_signoffs", "actions_per_tick", "canary"):
        groups: dict[Any, list[dict[str, Any]]] = {}
        for r in rows:
            groups.setdefault(r[knob], []).append(r)
        out[knob] = [{"value": v, "censored_mttr": sum(g["censored_mttr"] for g in rs) / len(rs),
                      "peak_drained": sum(g["peak_drained"] for g in rs) / len(rs),
                      "resolve_rate": sum(g["resolve_rate"] for g in rs) / len(rs)} for v, rs in groups.items()]
    return out


def render(result: dict[str, Any]) -> str:
    rows = sorted(result["rows"], key=lambda r: (r["censored_mttr"], r["peak_drained"]))
    head = ["", "drain cap", "sign-offs", "acts/tick", "canary", "censored MTTR", "MTTR (resolved)", "resolved",
            "peak drained", "sign-offs / risky action", "pages"]
    body = [["*" if r["pareto"] else "", f"{r['drain_cap']:.2f}", r["destructive_signoffs"], r["actions_per_tick"],
             "on" if r["canary"] else "off", r["censored_mttr"], r["mttr_resolved"], r["resolve_rate"],
             r["peak_drained"], r["signoffs_per_risky_action"], r["pages"]] for r in rows]
    pareto = sum(r["pareto"] for r in rows)
    parts = [f"## Monte Carlo policy sweep: {result['runs']} seeded runs "
             f"({result['configs']} configurations x {result['seeds']} paired storms)\n",
             "Each storm: 40 hosts, 10 random faults (drain-heavy mix) injected over ticks 3-20, 70 ticks, simulated "
             "on-call humans (first approval after 2 ticks, +1 tick per extra approval). Rows sorted by censored MTTR; "
             "`*` marks the "
             f"{pareto} Pareto-optimal configurations over (censored MTTR down, peak drained down, sign-offs up).\n",
             md_table(head, body, "lrrrrrrrrrr"), "",
             "### Marginal effect of each knob (mean over the other knobs)\n"]
    mrows = []
    for knob, vals in result["marginals"].items():
        for v in vals:
            mrows.append([knob, v["value"], v["censored_mttr"], v["peak_drained"], v["resolve_rate"]])
    parts += [md_table(["knob", "value", "censored MTTR", "peak drained", "resolved"], mrows, "lrrrr"), "",
              f"**Safety-invariant violations across all {result['runs']} runs: {result['violations']}** (must be 0)."]
    return "\n".join(parts)
