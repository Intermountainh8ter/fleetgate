"""The eval suite's own logic (table rendering, Pareto marking, the regression gate's comparison), on synthetic data."""
import copy
import json
import sys
from pathlib import Path

import pytest

EVALS = Path(__file__).resolve().parents[1] / "evals"
sys.path.insert(0, str(EVALS))

import _common  # noqa: E402
import montecarlo_eval  # noqa: E402
import regression_gate  # noqa: E402


def test_md_table_alignment_and_formatting():
    t = _common.md_table(["name", "n", "x"], [["a", 1, 0.5], ["bb", None, 123.456]])
    lines = t.splitlines()
    assert lines[0].startswith("| name") and set(lines[1]) <= set("|:- ")
    assert "0.500" in lines[2] and "123.5" in lines[3] and "| -" in lines[3]
    assert len({len(line) for line in lines}) == 1  # rectangular
    assert _common.md_table(["h"], []).count("\n") == 1  # header + separator only
    assert lines[1].split("|")[1].startswith(":")  # first column left-aligned, the rest right-aligned


def test_banner_is_explicit_about_idealisation():
    assert "IDEALISED" in _common.BANNER and "NOT evidence" in _common.BANNER
    assert set(_common.meta()) == {"python", "platform", "utc"}
    with _common.Timer() as t:
        pass
    assert t.seconds >= 0


def test_monte_carlo_config_grid_builds_valid_policies():
    cfg = montecarlo_eval.make_config(0.05, 3, 1, True)
    assert cfg.max_drained_fraction == 0.05 and cfg.max_actions_per_tick == 1 and cfg.canary["enabled"]
    assert cfg.approvals["DESTRUCTIVE"]["required"] == 3 and len(cfg.approvals["DESTRUCTIVE"]["roles"]) == 3
    assert cfg.name == "mc-cap5-so3-b1-canary"
    assert not montecarlo_eval.make_config(0.2, 1, 3, False).canary["enabled"]


def test_pareto_marking_uses_all_three_axes():
    def row(mttr, drained, so):
        return {"censored_mttr": mttr, "peak_drained": drained, "signoffs_per_risky_action": so}

    rows = [row(10, 0.1, 2.0),   # fast, mid exposure, strong review
            row(12, 0.1, 2.0),   # dominated by the first
            row(8, 0.2, 1.0),    # fastest but more exposed and less reviewed: non-dominated
            row(10, 0.1, 2.0),   # tie with the first: neither strictly dominates
            row(30, 0.05, None)]  # slow but least exposure (and no risky actions): non-dominated
    montecarlo_eval.mark_pareto(rows)
    assert [r["pareto"] for r in rows] == [True, False, True, True, True]
    m = montecarlo_eval.marginals([{**r, "drain_cap": 0.1, "destructive_signoffs": 1, "actions_per_tick": 3,
                                    "canary": False, "resolve_rate": 0.5} for r in rows])
    assert m["drain_cap"][0]["censored_mttr"] == pytest.approx((10 + 12 + 8 + 10 + 30) / 5)


GOOD = {
    "detection": {"flat": {"threshold": {"macro_recall": 1.0, "macro_f1": 1.0, "healthy_fp_incidents": 0}}},
    "policy": {"default/humans": {"resolve_rate": 0.9, "mttr_mean": 9.0, "violations": 0}},
    "montecarlo": {"best_censored_mttr": 17.0, "mean_resolve_rate": 0.75},
    "adversarial": {"violations": 0, "exceptions": 0},
}


def now_from(base, **patch):
    now = copy.deepcopy(base)
    now["scenario_failures"] = []
    now["montecarlo"].update({"violations": 0})
    for path, value in patch.items():
        node = now
        keys = path.split(".")
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return now


def test_gate_passes_on_identical_numbers_and_within_tolerance():
    assert regression_gate.compare(now_from(GOOD), GOOD) == []
    ok = now_from(GOOD, **{"detection.flat.threshold.macro_recall": 0.985,
                           "policy.default/humans.mttr_mean": 10.0, "montecarlo.best_censored_mttr": 19.0})
    assert regression_gate.compare(ok, GOOD) == []


@pytest.mark.parametrize("patch,needle", [
    ({"adversarial.violations": 1}, "adversarial safety"),
    ({"adversarial.exceptions": 2}, "exception"),
    ({"montecarlo.violations": 3}, "monte carlo sweep"),
    ({"policy.default/humans.violations": 1}, "policy sweep default/humans"),
    ({"detection.flat.threshold.macro_recall": 0.9}, "recall"),
    ({"detection.flat.threshold.macro_f1": 0.5}, "F1"),
    ({"detection.flat.threshold.healthy_fp_incidents": 5}, "healthy false positives"),
    ({"policy.default/humans.resolve_rate": 0.5}, "resolve rate"),
    ({"policy.default/humans.mttr_mean": 30.0}, "MTTR"),
    ({"montecarlo.best_censored_mttr": 40.0}, "best censored MTTR"),
    ({"montecarlo.mean_resolve_rate": 0.4}, "mean resolve rate"),
    ({"scenario_failures": ["scenario x [deny_all]: pages: expected <= 0, got 1"]}, "scenario x"),
])
def test_gate_flags_each_kind_of_regression(patch, needle):
    problems = regression_gate.compare(now_from(GOOD, **patch), GOOD)
    assert problems and any(needle in p for p in problems), problems


def test_scenario_failures_helper_is_empty_for_the_shipped_library():
    assert regression_gate.scenario_failures() == []


def test_baseline_file_is_present_and_complete():
    base = json.loads((EVALS / "baseline.json").read_text())
    assert {"detection", "policy", "adversarial", "montecarlo", "tolerance"} <= set(base)
    assert base["adversarial"]["violations"] == 0 and base["montecarlo"]["violations"] == 0
    assert set(base["detection"]) == {"flat", "diurnal"}
