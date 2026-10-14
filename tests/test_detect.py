import pytest

from fleetgate.detect import (
    DIRECTION,
    OPS,
    RULES,
    EWMADetector,
    MultiDetector,
    Rule,
    SeasonalDetector,
    ThresholdDetector,
    signal_metrics,
    summarize_evidence,
)
from fleetgate.fleet import Fleet, LoadPattern

HEALTHY = {"temp_c": 60.0, "fan_rpm": 7800.0, "service_up": 1.0, "packet_loss_pct": 0.0, "cpu_mhz": 3000.0}


def test_ops_table():
    assert OPS[">"](2, 1) and OPS["abs>"](-5, 3) and OPS["abs<"](-1, 3) and OPS["=="](1, 1) and OPS["<="](1, 1)


def test_rule_fires_and_missing_metric_never_fires():
    r = RULES["thermal"]
    assert r.fires({"temp_c": 90, "fan_rpm": 3000})
    assert not r.fires({"temp_c": 90})  # fan_rpm hidden (BMC down): cannot fire
    assert not r.fires({"temp_c": 70, "fan_rpm": 3000})
    assert r.metrics == ("temp_c", "fan_rpm")


def test_rule_margin_scales_toward_sensitivity():
    r = Rule("x", (("temp_c", ">", 100), ("fan_rpm", "<", 5000)))
    assert not r.fires({"temp_c": 90, "fan_rpm": 4000})
    assert r.fires({"temp_c": 90, "fan_rpm": 4000}, margin=0.8)  # more sensitive: threshold 80
    # for "<" rules a margin below 1 raises the threshold (5000 / 0.8 = 6250), also toward sensitivity
    assert r.fires({"temp_c": 90, "fan_rpm": 6000}, margin=0.8)
    assert not r.fires({"temp_c": 90, "fan_rpm": 7000}, margin=0.8)
    assert not r.fires({"temp_c": 110, "fan_rpm": 6000}, margin=1.0)
    assert not r.fires({"temp_c": 90, "fan_rpm": 4000}, margin=1.25)  # stricter: threshold 125


def test_threshold_detector_hysteresis_confirm_and_clear():
    d = ThresholdDetector(confirm_ticks=2, clear_ticks=3)
    bad = {**HEALTHY, "service_up": 0.0}
    assert d.observe(1, {"h1": bad}) == []  # one tick is not enough
    inc = d.observe(2, {"h1": bad})
    assert len(inc) == 1 and inc[0].signal == "service_down" and inc[0].host == "h1" and inc[0].detector == "threshold"
    assert d.observe(3, {"h1": bad}) == []  # still the same open incident
    assert d.open_signals("h1") == ["service_down"]
    for t in (4, 5):
        d.observe(t, {"h1": HEALTHY})
        assert d.open_signals("h1") == ["service_down"]  # not yet quiet for 3 ticks
    d.observe(6, {"h1": HEALTHY})
    assert d.open_signals("h1") == [] and len(d.closed) == 1
    d.observe(7, {"h1": bad})
    assert d.observe(8, {"h1": bad})  # a fresh incident after closing


def test_flapping_signal_below_confirm_never_opens():
    d = ThresholdDetector(confirm_ticks=2)
    bad = {**HEALTHY, "service_up": 0.0}
    for t in range(1, 20):
        assert d.observe(t, {"h1": bad if t % 2 else HEALTHY}) == []


def test_drained_host_closes_its_incidents():
    d = ThresholdDetector()
    bad = {**HEALTHY, "service_up": 0.0}
    d.observe(1, {"h1": bad})
    d.observe(2, {"h1": bad})
    d.observe(3, {})  # host no longer reports
    assert d.open_signals("h1") == [] and d.closed[-1][1].host == "h1"


def test_healthy_fleet_has_no_false_positives_for_threshold():
    f = Fleet(30, seed=11)
    d = ThresholdDetector()
    total = sum(len(d.observe(f.tick + 1, f.step())) for _ in range(150))
    assert total == 0


def test_signal_metrics_and_summarize_evidence():
    assert signal_metrics("thermal") == ("temp_c", "fan_rpm")
    assert signal_metrics("ewma:temp_c") == ("temp_c",) and signal_metrics("???") == ()
    d = ThresholdDetector(confirm_ticks=1)
    inc = d.observe(1, {"h1": {**HEALTHY, "service_up": 0.0}})[0]
    assert summarize_evidence(inc) == {"service_up": 0.0}
    inc.signal = "mystery"
    assert len(summarize_evidence(inc, limit=2)) == 2


def test_ewma_detects_a_spike_and_freezes_baseline():
    f = Fleet(10, seed=3)
    d = EWMADetector(warmup=10, z_threshold=4.0, confirm_ticks=2)
    for _ in range(25):
        assert d.observe(f.tick + 1, f.step()) == []
    f.inject("h001", "thermal")
    found = []
    for _ in range(10):
        found += d.observe(f.tick + 1, f.step())
    sigs = {i.signal for i in found if i.host == "h001"}
    assert "ewma:temp_c" in sigs and all(i.detector == "ewma" for i in found)
    st = d.stats[("h001", "temp_c")]
    assert st.mean < 70  # the anomaly was not absorbed into the baseline


def test_ewma_ignores_drops_in_up_only_metrics_and_respects_metric_filter():
    d = EWMADetector(warmup=3, metrics=["temp_c"], confirm_ticks=1)
    base = {"temp_c": 60.0, "service_up": 1.0}
    for t in range(1, 6):
        d.observe(t, {"h": {**base, "temp_c": 60.0 + (t % 2) * 0.5}})
    assert d.observe(6, {"h": {"temp_c": 50.0, "service_up": 0.0}}) == []  # colder is fine, service_up not tracked
    assert ("h", "service_up") not in d.stats
    assert d.observe(7, {"h": {"temp_c": 95.0, "service_up": 0.0}})[0].signal == "ewma:temp_c"


def test_directional_metrics_down_and_both():
    assert DIRECTION["service_up"] == "down" and DIRECTION["fan_rpm"] == "both"
    d = EWMADetector(warmup=5, confirm_ticks=1, metrics=["fan_rpm", "service_up"])
    for t in range(1, 10):
        d.observe(t, {"h": {"fan_rpm": 7800.0 + (t % 3) * 50, "service_up": 1.0}})
    sigs = {i.signal for i in d.observe(10, {"h": {"fan_rpm": 2500.0, "service_up": 0.0}})}
    assert sigs == {"ewma:fan_rpm", "ewma:service_up"}


def test_seasonal_detector_has_few_false_positives_under_a_strong_diurnal_swing():
    load = LoadPattern(period=48, amplitude=0.6)
    det = SeasonalDetector(period=48, bins=24, z_threshold=5.0, metrics=["cpu_util", "temp_c"])
    f = Fleet(15, seed=21, load=load)
    n = sum(len(det.observe(f.tick + 1, f.step())) for _ in range(48 * 5))
    assert n <= 1


def test_seasonal_detects_a_fault_injected_in_the_diurnal_trough():
    load = LoadPattern(period=48, amplitude=0.6)
    det = SeasonalDetector(period=48, bins=24, z_threshold=5.0, metrics=["temp_c", "fan_rpm"])
    f = Fleet(15, seed=21, load=load)
    for _ in range(48 * 4):
        det.observe(f.tick + 1, f.step())
    f.inject("h001", "thermal")
    sigs = set()
    for _ in range(6):
        sigs |= {i.signal for i in det.observe(f.tick + 1, f.step()) if i.host == "h001"}
    assert "seasonal:temp_c" in sigs


def test_seasonal_phase_bin_and_detection():
    d = SeasonalDetector(period=48, bins=8, confirm_ticks=1, min_obs=3, metrics=["temp_c"])
    assert d.phase_bin(0) == 0 and d.phase_bin(47) == 7 and d.phase_bin(48) == 0
    for t in range(1, 200):
        d.observe(t, {"h": {"temp_c": 60.0 + (t % 5) * 0.3}})
    inc = d.observe(200, {"h": {"temp_c": 99.0}})
    assert inc and inc[0].signal == "seasonal:temp_c" and inc[0].detector == "seasonal"


def test_multidetector_dedups_and_merges_open_views():
    a, b = ThresholdDetector(confirm_ticks=1), ThresholdDetector(confirm_ticks=1)
    multi = MultiDetector([a, b])
    out = multi.observe(1, {"h": {**HEALTHY, "service_up": 0.0}})
    assert len(out) == 1
    assert ("h", "service_down") in multi.open and multi.open_signals("h") == ["service_down"]
    assert multi.name == "multi"


@pytest.mark.parametrize("det", [ThresholdDetector(), EWMADetector(), SeasonalDetector()])
def test_detectors_tolerate_missing_metrics(det):
    for t in range(1, 30):
        det.observe(t, {"h": {"temp_c": 60.0}})  # nearly everything missing
    assert det.open_signals("h") == []
