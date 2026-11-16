"""Anchor x tamper matrix: deterministic, unanchored misses rehashed tampers, anchors catch replacement."""
from fleetgate.anchor_matrix import simulate


def test_deterministic():
    assert simulate(3, 4, 120, [10, 50]) == simulate(3, 4, 120, [10, 50])


def test_unanchored_and_anchored_rates():
    r = simulate(5, 6, 120, [10, 50])
    for iv in ("10", "50"):
        un = r["unanchored_undetected_rate_by_interval"][iv]
        an = r["undetected_rate_by_interval"][iv]
        assert un["inplace_edit"] == 0.0
        for c in ("rehashed_edit", "rehashed_delete", "rehashed_reorder", "tail_truncation",
                  "whole_log_replacement"):
            assert un[c] == 1.0
        assert an["whole_log_replacement"] == 0.0
        assert an["inplace_edit"] == 0.0
