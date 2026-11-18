"""False-block decomposition: determinism and count consistency."""
from fleetgate.false_block_eval import simulate


def test_deterministic():
    assert simulate(3, 80) == simulate(3, 80)


def test_counts_consistent():
    f = simulate(7, 120)["false_block"]
    assert f["n_benign"] == 120
    assert sum(f["by_reason"].values()) == f["n_deny"]
    assert 0.0 <= f["top_reason_share"] <= 1.0
    if f["n_deny"]:
        assert f["by_reason"][f["top_reason"]] == max(f["by_reason"].values())
