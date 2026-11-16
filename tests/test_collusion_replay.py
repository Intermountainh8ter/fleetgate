"""Collusion replay detector: flags breaches from the log alone and refuses tampered logs."""
import json
import random

import pytest

from fleetgate.audit import AuditLog
from fleetgate.collusion import FLEET_BUDGET, make_sequence, run_arm
from fleetgate.collusion_replay import _drop_middle_verdict, main, replay_flag, simulate


def test_replay_flags_per_call_breach_and_not_atomic():
    rng = random.Random(5)
    for _ in range(20):
        seq = make_sequence(rng)
        a, b = AuditLog(), AuditLog()
        run_arm("per_call_gate", seq, a)
        run_arm("atomic_gate", seq, b)
        assert replay_flag(a) is not None
        assert replay_flag(b) is None


def test_tampered_log_is_refused():
    log = AuditLog()
    run_arm("per_call_gate", make_sequence(random.Random(1)), log)
    with pytest.raises(ValueError):
        replay_flag(_drop_middle_verdict(log))


def test_simulate_deterministic_and_consistent():
    a = simulate(7, 30)
    assert a == simulate(7, 30)
    r = a["replay"]
    assert r["detection_rate"]["per_call_gate"] == 1.0
    assert r["false_flags"]["atomic_gate"] == 0
    assert r["tampered_log_rejection_rate"]["per_call_gate"] == 1.0
    assert a["config"]["fleet_budget"] == FLEET_BUDGET


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert main(["--seed", "7", "--n", "5", "--out", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["provenance"]["started_at"] and d["provenance"]["seeds"] == [7]
