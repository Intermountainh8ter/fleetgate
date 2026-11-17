"""Policy-profile hash replay: same profile never flips, hash stripping removes attribution."""
from fleetgate.policy import PolicyConfig
from fleetgate.policy_replay import flip_rate, log_stream, mutated_profile, profile_hash, simulate


def test_deterministic():
    assert simulate(3, 50) == simulate(3, 50)


def test_profile_hash_distinguishes_profiles():
    assert profile_hash(PolicyConfig()) == profile_hash(PolicyConfig())
    assert profile_hash(PolicyConfig()) != profile_hash(PolicyConfig.load("strict"))
    assert profile_hash(PolicyConfig()) != profile_hash(mutated_profile())


def test_same_profile_replay_is_stable():
    log = log_stream(1, 100, PolicyConfig())
    assert flip_rate(log, PolicyConfig()) == 0.0
    assert log.verify_full().ok


def test_attribution_and_strip():
    r = simulate(2, 100)
    assert r["attribution"]["attributable_with_hash"] == 100
    assert r["attribution"]["attributable_stripped"] == 0
    assert r["chain"]["verifies_with_hash_field"] is True
