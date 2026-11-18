"""Filtered false-block: determinism and count consistency."""
from fleetgate.filtered_false_block_eval import simulate


def test_deterministic():
    assert simulate(3, 80) == simulate(3, 80)


def test_counts_consistent():
    f = simulate(7, 120)["filtered_false_block"]
    assert f["n_benign"] == 120
    assert sum(f["by_reason"].values()) == f["n_deny"]
    assert f["n_eligible_pairs"] <= f["n_total_pairs"]
    assert f["n_precondition_failed"] == 0
