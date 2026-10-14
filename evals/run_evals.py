"""Run the eval suite and write real, reproducible results.

    python evals/run_evals.py                        # everything (a few minutes)
    python evals/run_evals.py --quick                # fewer seeds: what the CI regression gate uses
    python evals/run_evals.py --section adversarial  # one or more of: detection, policy, adversarial, montecarlo

Writes evals/results/results.json and evals/results/results.md (the numbers quoted in the README come from there).
Exit status is 1 if any safety-invariant violation was observed, otherwise 0.
"""
from __future__ import annotations

import argparse
import json
import sys

import adversarial_eval
import detection_eval
import montecarlo_eval
import policy_eval
from _common import BANNER, RESULTS_DIR, Timer, meta

SECTIONS = {"detection": detection_eval, "policy": policy_eval, "adversarial": adversarial_eval,
            "montecarlo": montecarlo_eval}


def violations(results: dict) -> int:
    n = 0
    n += results.get("adversarial", {}).get("total", {}).get("violations", 0)
    n += results.get("adversarial", {}).get("total", {}).get("exceptions", 0)
    n += sum(c["violations"] for c in results.get("policy", {}).get("cells", {}).values())
    n += results.get("montecarlo", {}).get("violations", 0)
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--section", default="all", help="comma-separated: detection,policy,adversarial,montecarlo")
    ap.add_argument("--quick", action="store_true", help="fewer seeds and scenarios (CI gate size)")
    ap.add_argument("--no-write", action="store_true", help="print only; do not touch evals/results/")
    a = ap.parse_args(argv)
    names = list(SECTIONS) if a.section == "all" else a.section.split(",")
    unknown = [n for n in names if n not in SECTIONS]
    if unknown:
        ap.error(f"unknown section(s): {', '.join(unknown)}")
    results: dict = {"meta": {**meta(), "quick": a.quick}}
    md = ["# fleetgate eval results\n", "```text", BANNER, "```\n",
          f"Generated {results['meta']['utc']} on Python {results['meta']['python']} "
          f"({'quick' if a.quick else 'full'} mode). All runs are seeded; re-running reproduces these numbers.\n"]
    print(BANNER + "\n")
    for name in names:
        mod = SECTIONS[name]
        with Timer() as t:
            res = mod.run(quick=a.quick)
        res["seconds"] = t.seconds
        results[name] = res
        text = mod.render(res)
        print(text + f"\n\n(section took {t.seconds}s)\n")
        md.append(text + f"\n\n_section took {t.seconds}s_\n")
    bad = violations(results)
    print(f"safety-invariant violations (all sections): {bad}")
    if not a.no_write:
        RESULTS_DIR.mkdir(exist_ok=True)
        suffix = "-quick" if a.quick else ""
        (RESULTS_DIR / f"results{suffix}.json").write_text(json.dumps(results, indent=1, default=str) + "\n")
        (RESULTS_DIR / f"results{suffix}.md").write_text("\n".join(md) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
