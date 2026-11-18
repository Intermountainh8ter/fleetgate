"""Regex baseline: determinism, the pattern's blind spots, and that the gate blocks every harmful variant."""
from fleetgate.regex_baseline_eval import build_regex, regex_blocks, simulate


def test_deterministic():
    assert simulate(3, 60, 20) == simulate(3, 60, 20)


def test_regex_is_case_sensitive_and_blind_to_unknowns():
    pat = build_regex({"decommission_host"})
    assert regex_blocks(pat, "decommission_host", "h")
    assert not regex_blocks(pat, "DECOMMISSION_HOST", "h")
    assert not regex_blocks(pat, "format_all_disks", "h")


def test_gate_blocks_all_harmful_and_counts_consistent():
    g = simulate(7, 100, 30)["gate"]
    assert g["n_harmful"] == 100 and g["n_benign"] == 30
    assert g["block_rate"] == 1.0
    assert g["block_rate_delta_vs_regex"] == g["block_rate"] - g["regex_block_rate"]
    assert sum(v["n"] for v in g["by_kind"].values()) == 100
