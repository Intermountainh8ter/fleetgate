"""Record the current outcome of every bundled scenario as its regression bounds.

    python scripts/calibrate_expectations.py            # show what would change
    python scripts/calibrate_expectations.py --write    # rewrite scenarios/*.json

Runs each scenario once with an approver that approves everything and once with one that denies everything, and
stores the observed results as `min` bounds (faults detected / resolved / contained) and `max` bounds (spurious
incidents, pages, verification failures, worst drained fraction). The runs are seeded, so the bounds are exact.
Only re-calibrate after you have reviewed *why* a result changed: this file is the regression baseline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fleetgate.orchestrator import approve_all, deny_all  # noqa: E402
from fleetgate.runner import run_scenario  # noqa: E402
from fleetgate.scenarios import Scenario, dumps_scenario, scenario_dir  # noqa: E402

MIN_KEYS = ("faults_detected", "faults_resolved", "faults_contained")
MAX_KEYS = ("spurious_incidents", "pages", "verify_failures", "max_drained_fraction")


def measure(scenario: Scenario, approver) -> dict:
    s = run_scenario(scenario, approver=approver).summary()
    return {"min": {k: s[k] for k in MIN_KEYS}, "max": {k: s[k] for k in MAX_KEYS}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="scenario names (default: all)")
    ap.add_argument("--write", action="store_true", help="rewrite the scenario files")
    ap.add_argument("--dir", default=None, help="scenario directory (default: ./scenarios)")
    a = ap.parse_args()
    changed = 0
    for path in sorted(scenario_dir(a.dir).glob("*.json")):
        doc = json.loads(path.read_text())
        if a.names and doc["name"] not in a.names:
            continue
        scenario = Scenario.from_dict(doc)
        doc["expect"] = {"approve_all": measure(scenario, approve_all), "deny_all": measure(scenario, deny_all)}
        new = dumps_scenario(doc)
        if new != path.read_text():
            changed += 1
            print(("updated " if a.write else "would update ") + path.name)
            if a.write:
                path.write_text(new)
    print(f"{changed} scenario file(s) {'rewritten' if a.write else 'differ'}")
    return 0 if a.write or not changed else 1


if __name__ == "__main__":
    sys.exit(main())
