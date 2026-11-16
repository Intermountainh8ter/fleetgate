import json

import pytest

from fleetgate import fleet_overdraw as fo
from fleetgate.audit import AuditLog


def test_per_agent_rule_overdraws():
    got = fo.admit("per_agent_rule", [fo.QUOTA] * 32, AuditLog(), "colluding", 32)
    assert sum(got) / fo.FLEET_LIMIT == 3.2


def test_cumulative_rule_caps_at_limit():
    for n in fo.SIZES:
        got = fo.admit("cumulative_rule", [fo.QUOTA] * n, AuditLog(), "colluding", n)
        assert sum(got) <= fo.FLEET_LIMIT


def test_over_quota_denied():
    assert fo.admit("per_agent_rule", [fo.QUOTA + 1], AuditLog(), "x", 1) == []


def test_unknown_arm():
    with pytest.raises(ValueError):
        fo.admit("nope", [1], AuditLog(), "x", 1)


def test_simulate_and_cli(tmp_path):
    r = fo.simulate(7, rounds=3)
    assert r["fleet_overdraw"]["benign_false_block_rate"]["cumulative_rule"] == 0.0
    assert all(r["verify_full_ok"].values()) and all(r["entries_equal_decisions"].values())
    out = tmp_path / "o.json"
    assert fo.main(["--seeds", "7", "--rounds", "2", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
