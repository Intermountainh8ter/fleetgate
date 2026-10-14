import pytest

from fleetgate.detect import EWMADetector, ThresholdDetector
from fleetgate.deteval import EvalResult, FaultStats, evaluate_detector, healthy_false_positives, sensitivity_sweep
from fleetgate.fleet import FAULT_SPECS, LoadPattern

FAST = {"seeds": 2, "fleet_size": 12, "warmup": 25, "horizon": 20}


def test_fault_stats_math():
    s = FaultStats("x", runs=10, detected=8, tp=12, fp=4, ttds=[1, 2, 2, 3, 4, 10])
    assert s.recall == 0.8 and s.precision == 0.75
    assert s.f1 == pytest.approx(2 * 0.75 * 0.8 / (0.75 + 0.8))
    assert s.ttd_mean == pytest.approx(22 / 6) and s.ttd_p90 == 10
    d = s.to_dict()
    assert d["recall"] == 0.8 and d["precision"] == 0.75 and d["ttd_p90"] == 10 and d["fault"] == "x"


def test_fault_stats_edge_cases():
    empty = FaultStats("e")
    assert empty.recall == 0.0 and empty.precision == 1.0 and empty.f1 == 0.0
    assert empty.ttd_mean is None and empty.ttd_p90 is None and empty.to_dict()["ttd_mean"] is None
    assert FaultStats("z", runs=1, detected=0, fp=3).precision == 0.0


def test_threshold_detector_finds_every_fault_with_no_false_positives():
    r = evaluate_detector(ThresholdDetector, **FAST)
    assert isinstance(r, EvalResult) and r.detector == "threshold"
    assert set(r.per_fault) == set(FAULT_SPECS)
    assert r.macro_recall == 1.0 and r.macro_f1 == 1.0 and r.false_positive_host_ticks == 0
    assert r.fp_rate == 0.0 and r.host_ticks > 0
    # time-to-detect: confirm_ticks=2 means detection needs >=2 ticks after injection (or the ramp, for gradual faults)
    step_faults = [f for f, s in FAULT_SPECS.items() if s.mode == "step" and not s.cascades]
    assert all(r.per_fault[f].ttd_mean >= 1 for f in step_faults)
    assert r.per_fault["service_down"].ttd_mean == 2.0
    # a gradual fault takes longer to cross its threshold than an abrupt one
    assert r.per_fault["memory_leak"].ttd_mean > r.per_fault["service_down"].ttd_mean


def test_exact_signal_counts_and_to_dict():
    r = evaluate_detector(ThresholdDetector, faults=["service_down", "nic_errors"], **FAST)
    assert r.per_fault["service_down"].exact == 2 and r.per_fault["service_down"].tp >= 2
    d = r.to_dict()
    assert set(d) >= {"detector", "macro_f1", "macro_recall", "false_positives", "host_ticks", "per_fault",
                      "fp_per_1k_host_ticks"}
    assert d["per_fault"]["nic_errors"]["recall"] == 1.0


def test_ewma_misses_a_slow_ramp_that_threshold_catches():
    kw = {"faults": ["memory_leak"], "seeds": 3, "fleet_size": 12, "warmup": 40, "horizon": 40}
    thr = evaluate_detector(ThresholdDetector, **kw)
    ewma = evaluate_detector(EWMADetector, **kw)
    assert thr.per_fault["memory_leak"].recall == 1.0
    assert ewma.per_fault["memory_leak"].recall < 1.0  # the adaptive baseline absorbs the ramp ("boiling frog")


def test_cascaded_detections_are_not_false_positives():
    r = evaluate_detector(ThresholdDetector, faults=["fan_failure"], **FAST)
    st = r.per_fault["fan_failure"]
    assert st.fp == 0 and st.tp >= 2  # thermal / cpu_throttling cascade on the same host is a real anomaly


def test_name_noise_scale_and_load_arguments_are_honoured():
    r = evaluate_detector(ThresholdDetector, faults=["service_down"], name="custom", noise_scale=0.0,
                          load=LoadPattern(amplitude=0.3), **FAST)
    assert r.detector == "custom" and r.per_fault["service_down"].recall == 1.0


def test_sensitivity_sweep_trades_recall_for_false_positives():
    pts = sensitivity_sweep(lambda m: ThresholdDetector(margin=m), [0.4, 1.0, 1.6], faults=["thermal", "disk_latency"],
                            **FAST)
    assert [p.param for p in pts] == [0.4, 1.0, 1.6]
    assert pts[0].fp_per_1k >= pts[1].fp_per_1k >= 0
    assert pts[1].macro_recall >= pts[2].macro_recall
    assert pts[0].to_dict()["param"] == 0.4 and "ttd_mean" in pts[0].to_dict()


def test_healthy_false_positives_counts_incidents_on_clean_fleets():
    n, host_ticks = healthy_false_positives(ThresholdDetector, fleets=2, fleet_size=15, ticks=40)
    assert n == 0 and host_ticks == 2 * 15 * 40
    noisy, _ = healthy_false_positives(lambda: ThresholdDetector(margin=0.1), fleets=1, fleet_size=15, ticks=30)
    assert noisy > 0  # absurdly tight thresholds do fire on healthy hosts
