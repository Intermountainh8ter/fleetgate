"""Gate-restart campaigns: campaign and budget state live in the Policy instance, not in the audit log."""
import pytest

from fleetgate.audit import AuditLog
from fleetgate.gate_restart import main, run_round, simulate
from fleetgate.split_caller import _fleet, admissible_runbooks


def test_deterministic_and_arms():
    a = simulate(3, 40)
    assert a == simulate(3, 40)
    r = a["admit_rate_by_arm"]
    assert r["restart_each"] == 1.0
    assert r["persistent"] <= 0.34
    assert r["state_carry"] == r["persistent"] == r["config_swap"]
    assert all(a["verify_full_ok"].values())
    assert all(a["entries_equal_decisions"].values())


def test_single_round():
    rb = admissible_runbooks()[0]
    hosts = list(_fleet().hosts)[:7]
    assert run_round("restart_each", rb, hosts, AuditLog(), 0) == 7
    assert run_round("persistent", rb, hosts, AuditLog(), 0) <= 2


def test_unknown_arm():
    with pytest.raises(ValueError):
        run_round("nope", "x", [], AuditLog(), 0)


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert main(["--seed", "1", "--rounds", "10", "--out", str(out)]) == 0
    assert "started_at" in out.read_text()
