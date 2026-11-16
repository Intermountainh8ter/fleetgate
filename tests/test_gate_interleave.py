"""Stale-read interleaving of the real gate: deterministic, sequential and recheck arms never breach."""
import pytest

from fleetgate.audit import AuditLog
from fleetgate.gate_interleave import main, run_round, simulate


def test_deterministic_and_arms():
    a = simulate(3, 60)
    assert a == simulate(3, 60)
    r = a["real_gate_interleave"]
    assert r["breach_rate"]["sequential"] == 0.0
    assert r["breach_rate"]["recheck"] == 0.0
    assert r["breach_rate"]["stale_read"] > 0.0
    assert all(r["verify_full_ok"].values())


def test_single_round_stale_read_breaches_floor():
    assert run_round("stale_read", 3, 3, AuditLog(), 0)["breach"] is True
    assert run_round("sequential", 3, 3, AuditLog(), 0)["breach"] is False


def test_unknown_arm():
    with pytest.raises(ValueError):
        run_round("nope", 3, 2, AuditLog(), 0)


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert main(["--seed", "1", "--n", "10", "--out", str(out)]) == 0
    assert "started_at" in out.read_text()
