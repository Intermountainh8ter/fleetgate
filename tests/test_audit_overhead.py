"""Audit overhead measurement: counters are deterministic and the chain verifies."""
import hashlib

from fleetgate import audit
from fleetgate.audit_overhead import simulate


def test_small_scales_deterministic_and_verified():
    a = simulate(3, (100, 400))
    assert a == simulate(3, (100, 400))
    assert all(v["verify_ok"] for v in a["scales"].values())
    assert a["scales"]["100"]["checkpoints"] >= 3


def test_hashlib_restored_after_run():
    simulate(1, (50, 60))
    assert audit.hashlib is hashlib
