"""Argument mutation suite: determinism, coverage of classes, Wilson bound, and that mutation changes the input."""
import random

from fleetgate.mutation_eval import CLASSES, mutate, simulate, wilson


def test_deterministic():
    assert simulate(3, 60) == simulate(3, 60)


def test_all_classes_covered_and_none_pass():
    m = simulate(7, 100)["mutation"]
    assert set(m["n"]) == set(CLASSES) | {"overall"}
    assert m["n"]["overall"] == 100
    assert m["pass_rate"]["overall"] == 0.0


def test_wilson_upper_bound_below_one_percent_at_480():
    assert wilson(0, 480)[1] < 0.01
    assert wilson(0, 0) == (0.0, 1.0)


def test_mutations_differ_from_input_mostly():
    rng = random.Random(1)
    for cls in CLASSES:
        outs = [mutate(cls, "decommission_host", rng) for _ in range(50)]
        assert any(o != "decommission_host" for o in outs)
