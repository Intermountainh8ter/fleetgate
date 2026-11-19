"""Base-rate sweep: default gate clears colluders, cumulative rule blocks them with no benign false blocks."""
import json

from fleetgate.collusion_base_rate import main, simulate


def test_deterministic_and_arms():
    a = simulate(3, 30)
    assert a == simulate(3, 30)
    r = a["collusion_base_rate"]
    assert r["verify_full_ok"] is True
    for v in r["by_base_rate"].values():
        assert v["n_colluders"] + v["n_benign"] == 30
        assert v["cumulative_rule_clear_rate"] in (0.0, None)
        assert v["cumulative_rule_benign_false_block_rate"] in (0.0, None)
    assert r["default_policy_clear_rate_at_0.5"] == 1.0


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "o.json"
    assert main(["--seed", "1", "--n-sequences", "10", "--out", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["provenance"]["seeds"] == [1]
    assert "started_at" in d["provenance"]
