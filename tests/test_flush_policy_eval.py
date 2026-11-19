"""Flush-policy driver: deterministic, per-append never loses, chain alone misses truncation."""
from fleetgate.flush_policy_eval import durable_at, flush_points, simulate


def test_deterministic():
    assert simulate(3, 20, 50, (1, 8)) == simulate(3, 20, 50, (1, 8))


def test_flush_points():
    assert flush_points("per_append", [2, 0, 1]) == [1, 2, 3]
    assert flush_points("group_commit", [2, 0, 1]) == [2, 3]
    assert flush_points("every_32", [40]) == [32]
    assert durable_at([2, 3], 1) == 0 and durable_at([2, 3], 2) == 2


def test_per_append_lossless_and_others_lose():
    r = simulate(5, 60, 300, (1, 8))
    for a in ("1", "8"):
        c = r["cells"][a]
        assert c["per_append"]["flush_calls_per_decision"] == 1.0
        assert c["per_append"]["mean_entries_lost"] == 0.0
        assert c["every_32"]["mean_entries_lost"] > 0.0
    assert r["cells"]["8"]["group_commit"]["mean_entries_lost"] > 0.0
    assert r["cells"]["1"]["group_commit"]["mean_entries_lost"] == 0.0


def test_verify_full_accepts_truncated_logs():
    r = simulate(5, 60, 300, (8,))
    assert r["truncation"]["n_verified"] > 0
    assert r["truncation"]["chain_only_detection_share"] == 0.0
