import json
import random

import pytest

from fleetgate import authority_intersection as ai
from fleetgate.audit import AuditLog


def test_tree_size_and_levels():
    assert ai.tree_size() == 85
    assert [ai.level_of(i) for i in (0, 1, 4, 5, 20, 21, 84)] == [0, 1, 1, 2, 2, 3, 3]


def test_grant_arms():
    req, parent = frozenset({0, 6, 7}), frozenset({0, 1})
    assert ai.grant("union", req, parent) == req
    assert ai.grant("parent_copy", req, parent) == parent
    assert ai.grant("intersection", req, parent) == {0}
    with pytest.raises(ValueError):
        ai.grant("nope", req, parent)


def test_intersection_never_out_of_scope_union_does():
    r = ai.run_tree("intersection", random.Random(1), AuditLog(), "t", False)
    assert r["out_scope"] == 0
    assert ai.run_tree("union", random.Random(1), AuditLog(), "t", False)["out_scope"] > 0


def test_benign_not_blocked_by_intersection():
    assert ai.run_tree("intersection", random.Random(2), AuditLog(), "t", True)["blocked"] == 0


def test_simulate_and_cli(tmp_path):
    out = tmp_path / "r.json"
    assert ai.main(["--seeds", "7", "--rounds", "3", "--out", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["authority"]["out_of_scope_grants_intersection"] == 0
    assert d["authority"]["excess_parent_copy_mean"] > 0
    assert all(a["verify_full_ok"] and a["entries_equal_decisions"] for a in d["arms"].values())
    assert "started_at" in d["provenance"]
