"""Detector evaluation: precision / recall / F1 and time-to-detect per fault type, plus sensitivity sweeps.

Protocol: a fresh fleet runs healthy for `warmup` ticks (so adaptive baselines settle), one fault is
injected on one host, and the detector runs for `horizon` more ticks. A detection on the faulty
host whose signal is evidence about a metric the fault perturbs is a true positive; any other
detection in the run is a false positive (healthy host, or a metric the fault does not touch).
"""
from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .detect import BaseDetector, MultiDetector, signal_metrics
from .fleet import FAULT_SPECS, Fleet, LoadPattern

DetectorFactory = Callable[[], BaseDetector | MultiDetector]


@dataclass
class FaultStats:
    fault: str
    runs: int = 0
    detected: int = 0
    exact: int = 0
    tp: int = 0
    fp: int = 0
    ttds: list[int] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.detected / self.runs if self.runs else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def ttd_mean(self) -> float | None:
        return sum(self.ttds) / len(self.ttds) if self.ttds else None

    @property
    def ttd_p90(self) -> int | None:
        if not self.ttds:
            return None
        s = sorted(self.ttds)
        return s[min(len(s) - 1, int(round(0.9 * (len(s) - 1))))]

    def to_dict(self) -> dict[str, Any]:
        return {"fault": self.fault, "runs": self.runs, "detected": self.detected, "exact": self.exact, "tp": self.tp,
                "fp": self.fp, "recall": round(self.recall, 3), "precision": round(self.precision, 3),
                "f1": round(self.f1, 3), "ttd_mean": None if self.ttd_mean is None else round(self.ttd_mean, 2),
                "ttd_p90": self.ttd_p90}


@dataclass
class EvalResult:
    detector: str
    per_fault: dict[str, FaultStats]
    false_positive_host_ticks: int  # healthy-host detections
    host_ticks: int

    @property
    def macro_f1(self) -> float:
        return sum(s.f1 for s in self.per_fault.values()) / max(1, len(self.per_fault))

    @property
    def macro_recall(self) -> float:
        return sum(s.recall for s in self.per_fault.values()) / max(1, len(self.per_fault))

    @property
    def fp_rate(self) -> float:
        return self.false_positive_host_ticks / max(1, self.host_ticks)

    def to_dict(self) -> dict[str, Any]:
        return {"detector": self.detector, "macro_f1": round(self.macro_f1, 3),
                "macro_recall": round(self.macro_recall, 3),
                "false_positives": self.false_positive_host_ticks, "host_ticks": self.host_ticks,
                "fp_per_1k_host_ticks": round(1000 * self.fp_rate, 3),
                "per_fault": {k: v.to_dict() for k, v in self.per_fault.items()}}


def evaluate_detector(factory: DetectorFactory, faults: list[str] | None = None, seeds: int = 5, fleet_size: int = 20,
                      warmup: int = 30, horizon: int = 40, load: LoadPattern | None = None, name: str | None = None,
                      noise_scale: float = 1.0) -> EvalResult:
    faults = faults or list(FAULT_SPECS)
    per: dict[str, FaultStats] = {f: FaultStats(f) for f in faults}
    fp_total, host_ticks = 0, 0
    for fault in faults:
        touched = set(FAULT_SPECS[fault].metrics)
        for seed in range(seeds):
            fleet = Fleet(fleet_size, seed=1000 * seeds + seed, load=load or LoadPattern(), noise_scale=noise_scale)
            det = factory()
            rng = random.Random(seed)
            host = rng.choice(sorted(fleet.hosts))
            st = per[fault]
            st.runs += 1
            for _ in range(warmup):
                data = fleet.step()
                for _ in det.observe(fleet.tick, data):
                    fp_total += 1
                    st.fp += 1
                host_ticks += len(data)
            fleet.inject(host, fault)
            inject_tick = fleet.tick
            first: int | None = None
            for _ in range(horizon):
                data = fleet.step()
                for inc in det.observe(fleet.tick, data):
                    active = set(fleet.hosts[inc.host].faults)
                    touched_now = set().union(*(FAULT_SPECS[f].metrics for f in active)) if active else set()
                    if inc.host == host and (set(signal_metrics(inc.signal)) & touched or inc.signal == fault):
                        st.tp += 1
                        if first is None:
                            first = fleet.tick
                            st.detected += 1
                            if inc.signal == fault:
                                st.exact += 1
                    elif inc.host == host and (set(signal_metrics(inc.signal)) & touched_now):
                        st.tp += 1  # cascaded fault on the same host: a real anomaly, not a false alarm
                    else:
                        st.fp += 1
                        fp_total += 1
                host_ticks += len(data)
            if first is not None:
                st.ttds.append(first - inject_tick)
    return EvalResult(name or factory().name, per, fp_total, host_ticks)


@dataclass
class SweepPoint:
    param: float
    macro_recall: float
    fp_per_1k: float
    macro_f1: float
    ttd_mean: float | None

    def to_dict(self) -> dict[str, Any]:
        return {"param": self.param, "macro_recall": round(self.macro_recall, 3),
                "fp_per_1k": round(self.fp_per_1k, 3),
                "macro_f1": round(self.macro_f1, 3),
                "ttd_mean": None if self.ttd_mean is None else round(self.ttd_mean, 2)}


def sensitivity_sweep(make: Callable[[float], BaseDetector | MultiDetector], params: list[float], **kw: Any,
                      ) -> list[SweepPoint]:
    """ROC-style curve: recall vs false-positive rate as one sensitivity knob moves."""
    out: list[SweepPoint] = []
    for p in params:
        r = evaluate_detector(lambda p=p: make(p), name=f"sweep@{p}", **kw)
        ttds = [t for s in r.per_fault.values() for t in s.ttds]
        out.append(SweepPoint(p, r.macro_recall, 1000 * r.fp_rate, r.macro_f1, sum(ttds) / len(ttds) if ttds else None))
    return out


def healthy_false_positives(factory: DetectorFactory, fleets: int = 5, fleet_size: int = 30, ticks: int = 100,
                            load: LoadPattern | None = None, noise_scale: float = 1.0) -> tuple[int, int]:
    """(incidents, host_ticks) on fleets with no faults at all."""
    total, host_ticks = 0, 0
    for seed in range(fleets):
        fleet = Fleet(fleet_size, seed=5000 + seed, load=load or LoadPattern(), noise_scale=noise_scale)
        det = factory()
        for _ in range(ticks):
            data = fleet.step()
            total += len(det.observe(fleet.tick, data))
            host_ticks += len(data)
    return total, host_ticks
