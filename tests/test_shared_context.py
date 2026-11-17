"""Shared corrupted context: full correlation defeats the quorum arm; the re-deriving gate is unaffected."""
from fleetgate.shared_context import run_cell, simulate


def test_deterministic():
    assert simulate(3, 40) == simulate(3, 40)


def test_full_correlation_executes_all_quorum_none_gate():
    r = run_cell(1.0, 100, 1)
    assert r["executed_deny"]["quorum_trusted"] == 1.0
    assert r["executed_deny"]["gate_rederived"] == 0.0


def test_no_correlation_rarely_executes():
    assert run_cell(0.0, 300, 1)["executed_deny"]["quorum_trusted"] < 0.05


def test_gate_blocks_no_legitimate_and_logs_verify():
    r = simulate(2, 40)
    assert all(v == 0.0 for v in r["gate_rederived_blocked_legitimate_by_rho"].values())
    assert r["all_logs_verify"] is True
