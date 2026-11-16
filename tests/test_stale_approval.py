"""Stale approvals: a stored approval outlives a stricter PolicyConfig unless the gate is asked again."""
import pytest

from fleetgate.audit import AuditLog
from fleetgate.split_caller import _fleet
from fleetgate.stale_approval import BANNED, approvable_runbooks, main, run_plan, simulate


def test_deterministic_and_arms():
    a = simulate(3, 60)
    assert a == simulate(3, 60)
    r = a["stale_execute_rate_by_arm"]
    assert r["trust_stored_approval"] == 1.0
    assert r["re_evaluate"] == 0.0
    assert a["disagreements_on_still_allowed"] == 0
    assert all(a["verify_full_ok"].values())


def test_single_plan():
    host = next(iter(_fleet().hosts))
    assert run_plan("trust_stored_approval", BANNED, host, AuditLog(), 0) == (True, True)
    assert run_plan("re_evaluate", BANNED, host, AuditLog(), 0) == (False, True)


def test_pool_and_unknown_arm():
    assert BANNED in approvable_runbooks()
    with pytest.raises(ValueError):
        run_plan("nope", BANNED, "x", AuditLog(), 0)


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert main(["--seed", "1", "--rounds", "10", "--out", str(out)]) == 0
    assert "started_at" in out.read_text()
