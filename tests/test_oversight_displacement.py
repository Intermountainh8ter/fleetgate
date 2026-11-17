"""Oversight displacement: an adaptive caller moves unsafe attempts off the gated path."""
from fleetgate.oversight_displacement import run_cell, simulate


def test_deterministic():
    assert simulate(3, 2, 50) == simulate(3, 2, 50)


def test_s0_both_execute_all():
    c = run_cell(0.0, 3, 1, 50)
    assert c["unsafe_executions_per_1000"] == c["all_paths_unsafe_executions_per_1000"] == 1000


def test_s1_all_paths_blocks_one_queue_leaks():
    c = run_cell(1.0, 3, 1, 100)
    assert c["all_paths_unsafe_executions_per_1000"] == 0
    assert c["unsafe_executions_per_1000"] > 900
