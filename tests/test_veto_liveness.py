"""Veto collusion: a single reject blocks the quorum arm; the re-deriving gate is unaffected."""
from fleetgate.veto_liveness import run_cell, simulate


def test_deterministic():
    assert simulate(3, 40) == simulate(3, 40)


def test_three_vetoers_block_everything_gate_none():
    r = run_cell(3, 200, 1)
    assert r["blocked"]["quorum_trusted"] == 1.0
    assert r["blocked"]["gate_rederived"] == 0.0


def test_no_vetoers_mostly_passes():
    assert run_cell(0, 400, 1)["blocked"]["quorum_trusted"] < 0.5


def test_gate_never_executes_deny_and_logs_verify():
    r = simulate(2, 40)
    assert r["gate_rederived_executed_deny_total"] == 0
    assert r["all_logs_verify"] is True
