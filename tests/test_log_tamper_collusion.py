import json

from fleetgate import log_tamper_collusion as lt
from fleetgate.subtree_collusion import QUOTA, SUBTREES, subtree_size


def _reqs():
    return [(t, QUOTA) for t in range(SUBTREES) for _ in range(subtree_size())]


def test_untampered_breach_is_caught_by_replay():
    log, _ = lt.write_log(_reqs(), "c")
    assert lt.replay_breach(log, _reqs())


def test_concealed_log_passes_chain_only_but_not_anchored():
    reqs = _reqs()
    log, anchor = lt.write_log(reqs, "c")
    tampered, victims = lt.conceal(log, reqs)
    assert victims
    assert tampered.verify_full().ok
    assert not lt.flagged(tampered, reqs, None)
    assert lt.flagged(tampered, reqs, anchor.roots)


def test_simulate_shape():
    t = lt.simulate(7, 3)["tamper"]
    assert t["undetected_breaches_writable_log"] == 1.0
    assert t["undetected_breaches_anchored"] == 0.0
    assert t["benign_false_flag_chain_only"] == 0


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert lt.main(["--seeds", "7", "--rounds", "2", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
