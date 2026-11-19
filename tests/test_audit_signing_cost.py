"""Signing-cost driver: deterministic, one signature per entry, keyless verify leaves signatures unchecked."""
from fleetgate.audit_signing_cost import run_fleet, simulate


def test_deterministic():
    assert simulate(3, (5, 10), 4) == simulate(3, (5, 10), 4)


def test_one_signature_per_entry():
    r = run_fleet(7, 10, 20)
    assert r["append_hmac_ops"] == r["entries"]
    assert r["entries"] > r["decisions"]
    assert r["keyed_verify_ok"] and r["keyed_verify_signature_compares"] == r["entries"]


def test_keyless_unchecked():
    r = run_fleet(7, 10, 20)
    assert r["keyless_verify_ok"] and r["keyless_unchecked_signatures"] == r["entries"]
