"""Shared plumbing for the eval suite: import path, table rendering, run metadata."""
from __future__ import annotations

import platform
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

RESULTS_DIR = Path(__file__).resolve().parent / "results"

BANNER = (
    "THE SIMULATOR IS IDEALISED. Faults are injected step/ramp/intermittent changes on Gaussian noise, a fix clears a\n"
    "fault after a fixed delay, thresholds were written by the same author as the faults, and humans are a latency\n"
    "model. These numbers show that the plumbing, the gate and the detectors behave as designed on a model of a\n"
    "fleet. They are NOT evidence about real BMC/SMART data, real operators, or real outage rates."
)


def md_table(headers: list[str], rows: list[list[Any]], align: str | None = None) -> str:
    """GitHub-flavoured markdown table (also readable as plain text)."""
    cells = [[_fmt(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    align = align or "l" + "r" * (len(headers) - 1)

    def line(vals: list[str]) -> str:
        return "| " + " | ".join(v.ljust(w) if a == "l" else v.rjust(w)
                                 for v, w, a in zip(vals, widths, align)) + " |"

    sep = "|" + "|".join((":" if a == "l" else "") + "-" * (w + 1) + (":" if a == "r" else "")
                         for w, a in zip(widths, align)) + "|"
    return "\n".join([line(headers), sep, *(line(r) for r in cells)])


def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.3f}" if abs(v) < 10 else f"{v:.1f}"
    return str(v)


def meta() -> dict[str, Any]:
    return {"python": platform.python_version(), "platform": platform.platform(terse=True),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


class Timer:
    def __enter__(self) -> Timer:
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self.seconds = round(time.perf_counter() - self.t0, 1)
