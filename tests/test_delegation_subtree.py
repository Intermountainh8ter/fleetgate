import json

import pytest

from fleetgate import delegation_subtree as ds
from fleetgate.audit import AuditLog


def _reqs(fanout, depth):
    return [(lv, ds.QUOTA) for lv in ds.tree_depths(fanout, depth)]


def test_tree_sizes():
    assert len(ds.tree_depths(4, 3)) == 85
    assert len(ds.tree_depths(4, 2)) == 21


def test_per_agent_overdraws():
    got = ds.admit("per_agent_rule", _reqs(4, 3), AuditLog(), "c", 4, 3)
    assert sum(got) / ds.ROOT_LIMIT == 8.5


def test_depth_cap_still_overdraws():
    got = ds.admit("depth_capped_rule", _reqs(4, 3), AuditLog(), "c", 4, 3)
    assert sum(got) / ds.ROOT_LIMIT == 2.1


def test_subtree_rule_caps():
    for f in ds.FANOUTS:
        for d in ds.DEPTHS:
            got = ds.admit("subtree_rule", _reqs(f, d), AuditLog(), "c", f, d)
            assert sum(got) <= ds.ROOT_LIMIT


def test_over_quota_and_unknown_arm():
    assert ds.admit("per_agent_rule", [(0, ds.QUOTA + 1)], AuditLog(), "x", 1, 0) == []
    with pytest.raises(ValueError):
        ds.admit("nope", [], AuditLog(), "x", 1, 0)


def test_simulate_and_cli(tmp_path):
    r = ds.simulate(7, rounds=2)
    assert r["delegation_subtree"]["benign_false_block_rate"]["subtree_rule"] == 0.0
    assert all(r["verify_full_ok"].values()) and all(r["entries_equal_decisions"].values())
    out = tmp_path / "o.json"
    assert ds.main(["--seeds", "7", "--rounds", "2", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
