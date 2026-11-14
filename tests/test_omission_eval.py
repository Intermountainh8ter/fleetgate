"""Omission detection: chain-only blind spots and the counter arm."""
import random

from fleetgate.omission_eval import KINDS, _build, _trial, simulate


def test_deterministic():
    assert simulate(3, 20) == simulate(3, 20)


def test_untampered_log_verifies_and_counts_match():
    log, issued = _build(random.Random(1))
    assert log.verify_full().ok
    assert len(log.of_kind("gate_verdict")) == issued


def test_never_written_has_valid_chain_but_short_count():
    log, issued = _build(random.Random(2), 3)
    assert log.verify_full().ok
    assert len(log.of_kind("gate_verdict")) == issued - 3


def test_rates_shape():
    rates = simulate(5, 30)["omission"] if "omission" in simulate(5, 30) else simulate(5, 30)["detection_rate"]
    for kind in KINDS:
        assert rates[f"{kind}_with_counter"] == 1.0
    assert rates["middle_deletion_chain_only"] == 1.0
    assert rates["tail_truncation_chain_only"] == 0.0
    assert rates["never_written_chain_only"] == 0.0


def test_trial_returns_pair():
    chain, counter = _trial("tail_truncation", random.Random(9))
    assert (chain, counter) == (False, True)
