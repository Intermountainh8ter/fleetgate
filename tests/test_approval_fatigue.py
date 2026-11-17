"""Approval fatigue: decaying rejection raises unsafe approvals; the re-deriving gate is unaffected."""
from fleetgate.approval_fatigue import analytic_single, reject_probability, run_cell, simulate


def test_deterministic():
    assert simulate(3, 2) == simulate(3, 2)


def test_reject_probability_decays():
    assert reject_probability(0.0, 50) == 0.9
    assert reject_probability(0.05, 99) < reject_probability(0.05, 0)


def test_analytic_matches_d0():
    assert abs(analytic_single(0.0) - 0.1) < 1e-12


def test_fatigue_raises_approval_and_gate_blocks():
    lo, hi = run_cell(0.0, 20, 1), run_cell(0.05, 20, 1)
    assert hi["unsafe_approval_rate"] > lo["unsafe_approval_rate"]
    assert hi["two_approver_unsafe_approval_rate"] <= hi["unsafe_approval_rate"] + 0.1
    assert lo["gate_rederived_executed_unsafe"] == hi["gate_rederived_executed_unsafe"] == 0
