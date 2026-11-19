"""Bypass reconciliation: chain and gate-counter blind spots, executor-side detection."""
from fleetgate.bypass_reconcile_eval import simulate


def test_deterministic():
    assert simulate(3, 20) == simulate(3, 20)


def test_arms():
    b = simulate(5, 60)["bypass"]
    assert b["rounds_with_bypass"] > 0
    assert b["detected_share_chain_only"] == 0.0
    assert b["detected_share_gate_counter"] == 0.0
    assert b["detected_share_reconcile"] == 1.0
    assert b["false_flag_rate_reconcile"] == 0.0


def test_no_bypass_no_flags():
    b = simulate(5, 20, bypass_p=0.0)["bypass"]
    assert b["rounds_with_bypass"] == 0
    assert b["false_flag_rate_chain_only"] == b["false_flag_rate_gate_counter"] == 0.0
    assert b["false_flag_rate_reconcile"] == 0.0
