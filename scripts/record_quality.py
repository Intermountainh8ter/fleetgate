"""Run the test-suite under coverage and record the real numbers in evals/results/quality.json.

    python scripts/record_quality.py

The README's test count and coverage figures are generated from that file by scripts/gen_docs.py, so they can only
ever be numbers that this script actually measured. Run it after the last code change, then run gen_docs.py.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        cov = Path(tmp) / "cov.json"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--cov", f"--cov-report=json:{cov}"],
            cwd=ROOT, capture_output=True, text=True)
        sys.stdout.write(proc.stdout[-1500:])
        if proc.returncode != 0:
            print("tests failed; not recording", file=sys.stderr)
            return proc.returncode
        m = re.search(r"(\d+) passed", proc.stdout)
        if not m:
            print("could not find the pytest summary line", file=sys.stderr)
            return 1
        totals = json.loads(cov.read_text())["totals"]
    out = {
        "tests": int(m.group(1)),
        "coverage_total": round(totals["percent_covered"], 1),  # line + branch, as configured in pyproject.toml
        "coverage_lines": round(100 * totals["covered_lines"] / totals["num_statements"], 1),
        "statements": totals["num_statements"],
        "python": platform.python_version(),
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    dest = ROOT / "evals" / "results" / "quality.json"
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(f"recorded {out} -> {dest.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
