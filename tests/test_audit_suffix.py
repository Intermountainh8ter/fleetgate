"""Suffix verification: constant cost, detects only tampers after the anchor."""
import hashlib

from fleetgate import audit
from fleetgate.audit_suffix import simulate


def test_small_scales_behaviour():
    a = simulate(3, (200, 800))
    assert a == simulate(3, (200, 800))
    assert a["all_untampered_ok"]
    for v in a["scales"].values():
        assert v["detect_rate"]["after"] == {"suffix": 1.0, "full": 1.0}
        assert v["detect_rate"]["before"] == {"suffix": 0.0, "full": 1.0}
    assert a["verify_full_ops_ratio_100k_over_1k"] > 3
    assert 0.9 <= a["hash_ops_ratio_100k_over_1k"] <= 1.1


def test_hashlib_restored():
    simulate(1, (100, 120))
    assert audit.hashlib is hashlib
