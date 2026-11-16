"""Split-action rounds: a per-action gate admits a composite split over ticks; a cumulative rule does not."""
import json

import pytest

from fleetgate.audit import AuditLog
from fleetgate.cli import main as cli_main
from fleetgate.split_action import admissible_runbooks, run_sequence, simulate
from fleetgate.split_caller import _fleet


def test_deterministic_and_arms():
    a = simulate(3, 20)
    assert a == simulate(3, 20)
    c = a["collusion"]
    assert c["default_policy_composite_admit_rate_depth8"] == 1.0
    assert c["cumulative_rule_composite_admit_rate_depth8"] == 0.0
    assert c["benign_false_block_rate_cumulative_rule"] == 0.0
    assert all(a["verify_full_ok"].values())
    assert all(a["entries_equal_decisions"].values())


def test_sequence_counts():
    pool = admissible_runbooks()[:8]
    rack = next(iter(_fleet().topology.racks.values()))
    steps = list(zip(pool, rack.hosts[:8]))
    assert run_sequence("default_policy", steps, AuditLog(), 0, "t") == 8
    assert run_sequence("cumulative_rule", steps, AuditLog(), 0, "t") == 4
    assert run_sequence("quota_per_role", steps, AuditLog(), 0, "t") == 4


def test_unknown_arm():
    with pytest.raises(ValueError):
        run_sequence("nope", [], AuditLog(), 0, "t")


def test_cli_routes_and_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert cli_main(["split-action", "--seeds", "1", "--rounds", "5", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert "started_at" in data["provenance"]
    assert data["collusion"]["default_policy_composite_admit_rate_depth8"] == 1.0
