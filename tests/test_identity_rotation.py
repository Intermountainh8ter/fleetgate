import json
import random

import pytest

from fleetgate import identity_rotation as ir
from fleetgate.audit import AuditLog


def test_per_agent_rule_admits_every_rotation():
    n, _ = ir.run_colluder("per_agent_rule", AuditLog(), True, random.Random(1))
    assert n == ir.ATTEMPTS


def test_cumulative_rule_caps_rotation():
    n, _ = ir.run_colluder("cumulative_rule", AuditLog(), True, random.Random(1))
    assert n == ir.CUMULATIVE_BUDGET


def test_static_colluder_capped_by_per_agent_rule():
    n, _ = ir.run_colluder("per_agent_rule", AuditLog(), False, random.Random(1))
    assert n == ir.PER_AGENT_BUDGET


def test_benign_not_blocked():
    for arm in ir.ARMS:
        assert ir.run_benign(arm, AuditLog())[0] == 0


def test_unknown_arm():
    with pytest.raises(ValueError):
        ir.Gate("nope", AuditLog(), "x")


def test_simulate_and_cli(tmp_path):
    r = ir.simulate(7, rounds=3)
    assert r["identity_rotation"]["rotating_colluder_admit_count_cumulative_rule"] == 4
    assert all(r["verify_full_ok"].values()) and all(r["entries_equal_decisions"].values())
    out = tmp_path / "o.json"
    assert ir.main(["--seeds", "7", "--rounds", "2", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
