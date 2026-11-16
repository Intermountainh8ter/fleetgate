"""Serialised-append driver: counts are deterministic, chain verifies, stale head is caught."""
import hashlib

from fleetgate import audit
from fleetgate.serialised_append import make_stream, simulate


def test_deterministic_and_stream_shape():
    assert simulate(3, 4, 300) == simulate(3, 4, 300)
    assert len(make_stream(3, 4, 300)) == 300


def test_serialised_chain_one_op_per_record_and_verifies():
    r = simulate(5, 8, 400)
    assert r["overhead"]["hash_ops_per_record_by_log"]["chain_serialised"] == 1.0
    assert r["overhead"]["hash_ops_per_record_by_log"]["plain"] == 0.0
    assert r["arms"]["chain_serialised"]["verify_ok"] is True
    assert r["arms"]["chain_serialised_checkpointed"]["verify_ok"] is True


def test_stale_head_fails_verification():
    r = simulate(5, 8, 2000)
    assert r["arms"]["chain_stale_head"]["collisions"] > 0
    assert r["stale_head_detected"] is True


def test_hashlib_restored():
    simulate(1, 2, 50)
    assert audit.hashlib is hashlib
