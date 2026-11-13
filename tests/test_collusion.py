"""Collusion simulation: each arm behaves as specified and the run is deterministic."""
import random

import pytest

from fleetgate.audit import AuditLog
from fleetgate.collusion import FLEET_BUDGET, PER_CALL_CAP, main, make_sequence, run_arm, simulate


def test_sequences_are_sub_cap_and_violate_in_aggregate():
    rng = random.Random(3)
    for _ in range(50):
        seq = make_sequence(rng)
        assert all(1 <= u <= PER_CALL_CAP for s in seq for u in s)
        assert sum(map(sum, seq)) > FLEET_BUDGET


def test_atomic_never_exceeds_budget_and_per_call_admits_all():
    rng = random.Random(4)
    for _ in range(50):
        seq = make_sequence(rng)
        assert run_arm("atomic_gate", seq, AuditLog()) <= FLEET_BUDGET
        assert run_arm("per_call_gate", seq, AuditLog()) == sum(map(sum, seq))


def test_unknown_arm_rejected():
    with pytest.raises(ValueError):
        run_arm("nope", [[1]], AuditLog())


def test_simulate_deterministic_and_chains_verify():
    a, b = simulate(7, 40), simulate(7, 40)
    assert a == b
    assert all(a["collusion"]["audit_chain_verified"].values())
    assert a["collusion"]["pass_through_rate"]["atomic_gate"] == 0.0
    assert a["collusion"]["pass_through_rate"]["per_call_gate"] == 1.0


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert main(["--seed", "7", "--n", "10", "--out", str(out)]) == 0
    import json
    d = json.loads(out.read_text())
    assert d["provenance"]["started_at"] and d["provenance"]["seeds"] == [7]
