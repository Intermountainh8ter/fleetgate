import json

import pytest

from fleetgate import subtree_collusion as sc
from fleetgate.audit import AuditLog


def _reqs():
    n = sc.subtree_size()
    return [(t, sc.QUOTA) for t in range(sc.SUBTREES) for _ in range(n)]


def test_subtree_size():
    assert sc.subtree_size() == 21


def test_per_agent_only_overdraws():
    assert sum(sc.admit("per_agent_only", _reqs(), AuditLog(), "c")) / sc.ROOT_LIMIT == 6.3


def test_per_subtree_overdraws_root():
    assert sum(sc.admit("per_subtree", _reqs(), AuditLog(), "c")) / sc.ROOT_LIMIT == 1.5


def test_root_atomic_caps():
    assert sum(sc.admit("root_atomic", _reqs(), AuditLog(), "c")) == sc.ROOT_LIMIT


def test_unknown_arm():
    with pytest.raises(ValueError):
        sc.admit("nope", [], AuditLog(), "c")


def test_over_quota_denied():
    assert sc.admit("root_atomic", [(0, sc.QUOTA + 1)], AuditLog(), "c") == []


def test_simulate_and_cli(tmp_path):
    out = tmp_path / "r.json"
    assert sc.main(["--seeds", "7", "--rounds", "3", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    res = data["subtree_collusion"]
    assert res["breaches_root_atomic"] == 0
    assert res["breaches_per_subtree"] == 3
    assert res["benign_false_block_rate"]["root_atomic"] == 0.0
    assert all(data["verify_full_ok"].values()) and all(data["entries_equal_decisions"].values())
    assert "started_at" in data["provenance"]


def test_cli_dispatch(tmp_path):
    from fleetgate.cli import main
    assert main(["subtree-collusion", "--rounds", "1", "--out", str(tmp_path / "x.json")]) == 0
