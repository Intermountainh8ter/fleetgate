from fleetgate import audit_query_cost as q


def test_small_fleet_counts():
    out = q.simulate(7, per_agent=20, sizes=(5, 10))
    assert out["records_scanned_per_query"]["index"] == {"5": 20.0, "10": 20.0}
    assert out["records_scanned_per_query"]["full_scan"]["10"] >= 200
    assert out["all_record_sets_identical"] and out["all_verifications_ok"]


def test_deterministic():
    assert q.simulate(3, 4, (4, 8)) == q.simulate(3, 4, (4, 8))


def test_main_writes_provenance(tmp_path):
    p = tmp_path / "r.json"
    assert q.main(["--seed", "7", "--decisions-per-agent", "3", "--out", str(p)]) == 0
    assert "started_at" in p.read_text()
