"""Collusion from a seeded onset: majority quorum inherits it, a re-deriving gate does not."""
from fleetgate.collusion_onset import run_cell, simulate


def test_deterministic():
    assert simulate(3, 40) == simulate(3, 40)


def test_unanimous_collusion_defeats_quorum_not_gate():
    r = run_cell(5, 200, 1)
    assert r["post"]["quorum_trusted"] == 1.0
    assert r["post"]["gate_rederived"] == 0.0 and r["pre"]["gate_rederived"] == 0.0
    assert r["policy_deny_share"] == 1.0 and r["benign_gate_exec_share"] == 1.0


def test_no_colluders_quorum_mostly_holds():
    r = run_cell(0, 400, 1)
    assert r["post"]["quorum_trusted"] < 0.1


def test_gate_zero_everywhere_and_logs_verify():
    r = simulate(2, 40)
    assert r["gate_rederived_max_share"] == 0.0
    assert r["all_logs_verify"] is True
