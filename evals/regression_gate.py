"""CI regression gate: fail the build if safety, detection, MTTR or scenario baselines regress.

    python evals/regression_gate.py                    # check against evals/baseline.json
    python evals/regression_gate.py --update-baseline  # record the current numbers (review the diff first!)

It runs the quick eval sections plus every bundled scenario's recorded expectations. Everything is seeded, so a
failure means behaviour changed, not that the dice were unkind. Safety violations are never tolerated; quality
metrics may drift within the tolerances recorded in baseline.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import adversarial_eval
import detection_eval
import montecarlo_eval
import policy_eval
from _common import BANNER, Timer

from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.runner import check_expectations, run_scenario
from fleetgate.scenarios import load_scenarios

BASELINE = Path(__file__).resolve().parent / "baseline.json"
TOLERANCE = {"detection_recall": 0.02, "detection_f1": 0.05, "resolve_rate": 0.03, "mttr_factor": 1.2,
             "mttr_slack": 0.5, "mc_mttr_factor": 1.15}


def scenario_failures() -> list[str]:
    bad: list[str] = []
    for name, s in sorted(load_scenarios().items()):
        for who, approver in (("approve_all", approve_all), ("deny_all", deny_all)):
            for msg in check_expectations(run_scenario(s, approver=approver).summary(), s.expect.get(who)):
                bad.append(f"scenario {name} [{who}]: {msg}")
    return bad


def measure() -> dict:
    out: dict = {}
    with Timer() as t:
        det = detection_eval.run(quick=True)
    out["detection"] = {regime: {d: {"macro_recall": v["macro_recall"], "macro_f1": v["macro_f1"],
                                     "healthy_fp_incidents": v["healthy_fp_incidents"]} for d, v in res.items()}
                        for regime, res in det["regimes"].items()}
    out["detection_seconds"] = t.seconds
    pol = policy_eval.run(quick=True)
    out["policy"] = {k: {"resolve_rate": c["resolve_rate"], "mttr_mean": c["mttr_mean"], "violations": c["violations"]}
                     for k, c in pol["cells"].items()}
    adv = adversarial_eval.run(quick=True)
    out["adversarial"] = {"violations": adv["total"]["violations"], "exceptions": adv["total"]["exceptions"],
                          "runs": adv["total"]["runs"], "gate_evaluations": adv["total"]["gate_evaluations"]}
    mc = montecarlo_eval.run(quick=True)
    out["montecarlo"] = {"violations": mc["violations"], "runs": mc["runs"],
                         "best_censored_mttr": min(r["censored_mttr"] for r in mc["rows"]),
                         "mean_resolve_rate": sum(r["resolve_rate"] for r in mc["rows"]) / len(mc["rows"])}
    out["scenario_failures"] = scenario_failures()
    return out


def compare(now: dict, base: dict) -> list[str]:
    tol = {**TOLERANCE, **base.get("tolerance", {})}
    bad: list[str] = list(now["scenario_failures"])
    if now["adversarial"]["violations"] or now["adversarial"]["exceptions"]:
        bad.append(f"adversarial safety: {now['adversarial']['violations']} violation(s), "
                   f"{now['adversarial']['exceptions']} exception(s)")
    if now["montecarlo"]["violations"]:
        bad.append(f"monte carlo sweep: {now['montecarlo']['violations']} safety violation(s)")
    for k, c in now["policy"].items():
        if c["violations"]:
            bad.append(f"policy sweep {k}: {c['violations']} safety violation(s)")
    for regime, dets in base["detection"].items():
        for d, b in dets.items():
            n = now["detection"][regime][d]
            if n["macro_recall"] < b["macro_recall"] - tol["detection_recall"]:
                bad.append(f"detection {regime}/{d}: recall {n['macro_recall']:.3f} < baseline {b['macro_recall']:.3f}")
            if n["macro_f1"] < b["macro_f1"] - tol["detection_f1"]:
                bad.append(f"detection {regime}/{d}: F1 {n['macro_f1']:.3f} < baseline {b['macro_f1']:.3f}")
            if n["healthy_fp_incidents"] > b["healthy_fp_incidents"] + 1:
                bad.append(f"detection {regime}/{d}: {n['healthy_fp_incidents']} healthy false positives "
                           f"(baseline {b['healthy_fp_incidents']})")
    for k, b in base["policy"].items():
        n = now["policy"][k]
        if n["resolve_rate"] < b["resolve_rate"] - tol["resolve_rate"]:
            bad.append(f"policy {k}: resolve rate {n['resolve_rate']:.3f} < baseline {b['resolve_rate']:.3f}")
        if b["mttr_mean"] is not None and n["mttr_mean"] is not None \
                and n["mttr_mean"] > b["mttr_mean"] * tol["mttr_factor"] + tol["mttr_slack"]:
            bad.append(f"policy {k}: MTTR {n['mttr_mean']:.2f} > baseline {b['mttr_mean']:.2f} x {tol['mttr_factor']}")
    b = base["montecarlo"]
    if now["montecarlo"]["best_censored_mttr"] > b["best_censored_mttr"] * tol["mc_mttr_factor"]:
        bad.append(f"monte carlo: best censored MTTR {now['montecarlo']['best_censored_mttr']:.2f} > "
                   f"baseline {b['best_censored_mttr']:.2f} x {tol['mc_mttr_factor']}")
    if now["montecarlo"]["mean_resolve_rate"] < b["mean_resolve_rate"] - tol["resolve_rate"]:
        bad.append(f"monte carlo: mean resolve rate {now['montecarlo']['mean_resolve_rate']:.3f} < "
                   f"baseline {b['mean_resolve_rate']:.3f}")
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--baseline", default=str(BASELINE))
    a = ap.parse_args(argv)
    print(BANNER + "\n")
    now = measure()
    path = Path(a.baseline)
    if a.update_baseline:
        if now["scenario_failures"] or now["adversarial"]["violations"] or now["montecarlo"]["violations"]:
            print("refusing to record a baseline that has safety violations or failing scenarios:")
            for m in now["scenario_failures"]:
                print("  -", m)
            return 1
        base = {k: v for k, v in now.items() if k not in ("scenario_failures", "detection_seconds")}
        base["tolerance"] = TOLERANCE
        path.write_text(json.dumps(base, indent=1) + "\n")
        print(f"baseline written to {path}")
        return 0
    base = json.loads(path.read_text())
    problems = compare(now, base)
    adv, mc = now["adversarial"], now["montecarlo"]
    print(f"adversarial: {adv['runs']} runs, {adv['gate_evaluations']} gate evaluations, "
          f"{adv['violations']} violations")
    print(f"monte carlo: {mc['runs']} runs, best censored MTTR {mc['best_censored_mttr']:.2f}")
    print(f"scenarios: {len(load_scenarios())} x 2 approvers checked against recorded expectations")
    if problems:
        print(f"\nREGRESSION GATE FAILED ({len(problems)} problem(s)):")
        for p in problems:
            print("  -", p)
        return 1
    print("\nregression gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
