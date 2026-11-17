"""Gate state cost: stateless and in-memory arms hash nothing; full re-verification scales with the log."""
import hashlib

from fleetgate import audit
from fleetgate.gate_state_cost import simulate


def test_small_scales_behaviour():
    a = simulate(3, (200, 800))
    assert a == simulate(3, (200, 800))
    assert a["verdicts_identical_all_scales"]
    ops = a["ops_per_decision_by_arm"]
    for n in ("200", "800"):
        assert ops["stateless"][n] == 0 and ops["in_memory"][n] == 0
        assert ops["log_derived_suffix"][n] < 100
    assert ops["log_derived_full"]["800"] > 3 * ops["log_derived_full"]["200"]
    ref = a["refusal_rate_after_tamper_by_arm"]
    for n in ("200", "800"):
        assert ref["log_derived_full"][n] == 1.0
        assert ref["in_memory"][n] == 0.0 and ref["log_derived_suffix"][n] == 0.0


def test_hashlib_restored():
    simulate(1, (100, 120))
    assert audit.hashlib is hashlib
