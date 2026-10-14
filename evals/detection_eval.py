"""Detection quality: precision / recall / F1 / time-to-detect per fault type for three detector families.

threshold  static rules with 2-tick hysteresis (what production alerting usually is)
ewma       per-(host, metric) exponentially weighted z-score, baseline frozen while anomalous
seasonal   per-(host, metric, phase-of-day) baseline with pooled residual variance

Two regimes: a flat load, and a strong diurnal swing (+-40%) where a time-blind baseline is expected to struggle.
Protocol (see fleetgate.deteval): warm up healthy, inject ONE fault on ONE host, watch 40 ticks. A detection on that
host about a metric the fault (or its cascade) perturbs is a true positive; anything else is a false positive.
"""
from __future__ import annotations

from typing import Any

import _common  # noqa: F401  (sets sys.path)
from _common import md_table

from fleetgate.detect import EWMADetector, SeasonalDetector, ThresholdDetector
from fleetgate.deteval import evaluate_detector, healthy_false_positives
from fleetgate.fleet import FAULT_SPECS, LoadPattern

DETECTORS = {
    "threshold": lambda: ThresholdDetector(),
    "ewma": lambda: EWMADetector(alpha=0.1, z_threshold=4.0, warmup=10),
    "seasonal": lambda: SeasonalDetector(period=48, bins=8, z_threshold=4.0),
}
# Every detector gets the same >= 3 diurnal cycles of healthy history before the fault, so a seasonal baseline is
# not handicapped by a protocol that only suits detectors without memory.
REGIMES = {
    "flat": {"load": LoadPattern(), "warmup": 150, "jitter": 47},
    "diurnal": {"load": LoadPattern(period=48, amplitude=0.4), "warmup": 150, "jitter": 47},
}


def run(quick: bool = False) -> dict[str, Any]:
    seeds = 2 if quick else 6
    out: dict[str, Any] = {"seeds": seeds, "horizon": 40, "fleet_size": 20, "regimes": {}}
    for regime, cfg in REGIMES.items():
        res: dict[str, Any] = {}
        for name, factory in DETECTORS.items():
            r = evaluate_detector(factory, seeds=seeds, fleet_size=20, warmup=cfg["warmup"], horizon=40,
                                  load=cfg["load"], name=name, warmup_jitter=cfg["jitter"])
            fp_n, fp_ticks = healthy_false_positives(factory, fleets=3 if quick else 8, fleet_size=30,
                                                     ticks=200 if regime == "diurnal" else 100, load=cfg["load"])
            ttds = [t for s in r.per_fault.values() for t in s.ttds]
            res[name] = {
                "macro_precision": sum(s.precision for s in r.per_fault.values()) / len(r.per_fault),
                "macro_recall": r.macro_recall, "macro_f1": r.macro_f1,
                "ttd_mean": sum(ttds) / len(ttds) if ttds else None,
                "fp_per_1k_host_ticks_in_fault_runs": 1000 * r.fp_rate,
                "healthy_fp_incidents": fp_n, "healthy_host_ticks": fp_ticks,
                "healthy_fp_per_1k_host_ticks": 1000 * fp_n / max(1, fp_ticks),
                "per_fault": {k: v.to_dict() for k, v in r.per_fault.items()},
            }
        out["regimes"][regime] = res
    return out


def render(result: dict[str, Any]) -> str:
    parts = [f"## Detection quality ({result['seeds']} seeds x {len(FAULT_SPECS)} fault types x one injected fault "
             f"per run, 20 hosts, {result['horizon']}-tick horizon)\n"]
    for regime, res in result["regimes"].items():
        rows = [[d, v["macro_precision"], v["macro_recall"], v["macro_f1"], v["ttd_mean"],
                 v["healthy_fp_per_1k_host_ticks"], v["healthy_fp_incidents"]] for d, v in res.items()]
        parts.append(f"### {regime} load: macro-averaged over fault types\n")
        parts.append(md_table(["detector", "precision", "recall", "F1", "mean TTD (ticks)",
                               "FP / 1k host-ticks (healthy)", "FP incidents (healthy)"], rows))
        parts.append("")
        det_names = list(res)
        rows = []
        for fault in FAULT_SPECS:
            row: list[Any] = [fault, FAULT_SPECS[fault].mode]
            for d in det_names:
                f = res[d]["per_fault"][fault]
                row += [f["recall"], f["f1"], f["ttd_mean"]]
            rows.append(row)
        hdr = ["fault", "onset"] + [f"{d[:4]} {m}" for d in det_names for m in ("R", "F1", "TTD")]
        parts.append(f"### {regime} load: per fault type (R = recall, TTD = mean ticks to detect, - = never)\n")
        parts.append(md_table(hdr, rows, "ll" + "r" * (len(hdr) - 2)))
        parts.append("")
    return "\n".join(parts)
