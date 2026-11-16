"""Split-caller rounds: shared gate keys nothing on caller identity, per-agent gates bypass the tick budget."""
import pytest

from fleetgate.audit import AuditLog
from fleetgate.split_caller import admissible_runbooks, main, run_round, simulate


def test_deterministic_and_arms():
    a = simulate(3, 60)
    assert a == simulate(3, 60)
    r = a["admit_rate_by_arm"]
    assert r["shared_gate"] == r["single_actor"]
    assert r["shared_gate"] < 0.9
    assert r["per_agent_gate"] >= 0.9
    assert all(a["verify_full_ok"].values())
    assert all(a["entries_equal_decisions"].values())


def test_single_round_budget():
    pool = admissible_runbooks()[:5]
    from fleetgate.split_caller import _fleet
    hosts = list(_fleet().hosts)[:5]
    assert run_round("shared_gate", pool, hosts, AuditLog(), 0) == 3
    assert run_round("per_agent_gate", pool, hosts, AuditLog(), 0) == 5


def test_unknown_arm():
    with pytest.raises(ValueError):
        run_round("nope", [], [], AuditLog(), 0)


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert main(["--seed", "1", "--rounds", "10", "--out", str(out)]) == 0
    assert "started_at" in out.read_text()
