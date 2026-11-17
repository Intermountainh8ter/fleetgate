"""Audit fleet cost: append and sampled proofs are cheap per decision, full verification grows with the log."""
import hashlib

from fleetgate import audit
from fleetgate.audit_fleet_cost import simulate


def test_small_fleets_behaviour():
    a = simulate(3, 20, (20, 80))
    assert a == simulate(3, 20, (20, 80))
    for n in ("20", "80"):
        r = a["hash_ops_per_decision_by_fleet_size"][n]
        assert r["full_verify_ok"] and r["sample_ok"]
        assert 1 <= r["chained_append"] <= 3.1
        assert r["sampled_tamper_detection"] == 1.0
        assert r["unsampled_tamper_detection"] == 0.0
    assert 3.5 < a["full_verification_total_ratio_largest_to_smallest"] < 4.5


def test_hashlib_restored():
    simulate(1, 10, (12, 14))
    assert audit.hashlib is hashlib
