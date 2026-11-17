"""Shared-input quorum: majority votes inherit a shared corruption, a re-deriving gate does not."""
from fleetgate.shared_quorum import run_cell, simulate


def test_deterministic():
    assert simulate(3, 30) == simulate(3, 30)


def test_full_sharing_defeats_quorum_not_gate():
    r = run_cell(1.0, 5, 50, 1)
    assert r["executed_deny_share"]["quorum_trusted"] == 1.0
    assert r["executed_deny_share"]["distinct_principal"] == 1.0
    assert r["executed_deny_share"]["gate_rederived"] == 0.0
    assert r["policy_deny_share"] == 1.0 and r["benign_gate_exec_share"] == 1.0


def test_no_sharing_quorum_mostly_holds():
    r = run_cell(0.0, 9, 200, 1)
    assert r["executed_deny_share"]["quorum_trusted"] < 0.05


def test_gate_zero_everywhere_and_logs_verify():
    r = simulate(2, 40)
    assert r["gate_rederived_max_share"] == 0.0
    assert r["all_logs_verify"] is True
    assert set(r["quorum_trusted_by_approvers_at_shared_1"].values()) == {1.0}
