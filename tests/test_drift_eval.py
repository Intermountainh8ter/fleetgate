"""Tool drift suite: determinism, gate behaviour per arm, Wilson bound."""
from fleetgate.drift_eval import fingerprint, make_tool, schema_valid, simulate


def test_deterministic():
    assert simulate(3, 60) == simulate(3, 60)


def test_hash_gate_blocks_semantic_drift_schema_gate_does_not():
    d = simulate(7, 480)["drift"]
    assert d["pass_rate"]["semantic_post_baseline"] == 0.0
    assert d["pass_rate"]["schema_only"]["semantic_post_baseline"] == 1.0
    assert d["wilson95_upper_semantic_post_baseline"] < 0.01


def test_first_listing_poison_passes_hash_gate():
    assert simulate(7, 60)["drift"]["pass_rate"]["first_listing_poison"] == 1.0


def test_benign_reword_flagged_and_structural_blocked():
    d = simulate(7, 60)["drift"]
    assert d["benign_flagged_as_drift_rate"] > 0
    assert d["pass_rate"]["structural_post_baseline"] == 0.0


def test_fingerprint_and_schema_validity():
    t = make_tool(0)
    assert schema_valid(t) and fingerprint(t) == fingerprint(dict(reversed(list(t.items()))))
    assert not schema_valid({"name": "x"})
