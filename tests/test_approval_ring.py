"""Approval ring: the gate arm ignores votes; a full ring defeats the quorum arms."""
from fleetgate.approval_ring import run_cell, simulate


def test_deterministic():
    assert simulate(3, 40) == simulate(3, 40)


def test_full_ring_executes_all_quorum_none_gate():
    r = run_cell(5, 100, 1)["executed_deny"]
    assert r["quorum_no_distinct_rule"] == 1.0
    assert r["quorum_distinct_proposer"] == 1.0
    assert r["gate_rederived"] == 0.0


def test_no_ring_rarely_executes():
    assert run_cell(0, 300, 1)["executed_deny"]["quorum_no_distinct_rule"] < 0.05


def test_gate_blocks_no_legitimate_and_logs_verify():
    r = simulate(2, 40)
    assert all(v == 0.0 for v in r["gate_rederived_blocked_legitimate_by_ring_size"].values())
    assert r["all_logs_verify"] is True
