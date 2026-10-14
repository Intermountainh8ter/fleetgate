"""Audit log: Merkle checkpoints, HMAC signatures, external anchors, tamper detection, replay."""
import copy
import json

from fleetgate.audit import ENV_KEY, AuditLog, FileAnchor, MemoryAnchor, ReplayState, canonical, merkle_root, replay
from fleetgate.fleet import Fleet
from fleetgate.orchestrator import Orchestrator, approve_all


def build(n=20, key=None, every=4, anchor=None, path=None):
    a = AuditLog(path, key=key, checkpoint_every=every, anchor=anchor)
    for i in range(n):
        a.append("evt", n=i, who="alice")
    return a


def rewrite(entries, key=None, every=4):
    """The attacker's best move without the key: rebuild the whole chain (and checkpoints) from edited bodies."""
    b = AuditLog(key=key, checkpoint_every=every)
    for e in entries:
        if e["kind"] != "checkpoint":
            b.append(e["kind"], **{k: v for k, v in e.items() if k not in ("seq", "kind", "prev", "hash", "sig")})
    return b


# ---- merkle ---------------------------------------------------------------------------------------------


def test_merkle_root_properties():
    assert merkle_root([]) == "0" * 64
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    assert merkle_root([a]) != merkle_root([b])
    assert merkle_root([a, b]) != merkle_root([b, a])
    assert merkle_root([a, b, c]) == merkle_root([a, b, c])
    assert merkle_root([a, b, c]) != merkle_root([a, b])
    assert len(merkle_root([a, b, c])) == 64


def test_canonical_json_is_order_independent_and_ascii():
    assert canonical({"b": 1, "a": "é"}) == '{"a":"\\u00e9","b":1}'


# ---- checkpoints ----------------------------------------------------------------------------------------


def test_checkpoints_are_written_every_n_entries_and_verify():
    a = build(20, every=4)
    cps = a.of_kind("checkpoint")
    assert len(cps) == 5 and cps[0]["block_start"] == 0 and cps[0]["block_end"] == 4 and cps[0]["count"] == 4
    assert cps[1]["block_start"] == 5  # the checkpoint entry itself sits between blocks
    assert cps[1]["prev_root"] == cps[0]["merkle_root"]
    r = a.verify_full()
    assert r.ok and r.checkpoints == 5 and r.entries == len(a.entries) and not r.problems and not r.signed
    assert a.verify() == (True, None)


def test_manual_checkpoint_and_checkpointing_disabled():
    a = build(3, every=0)
    assert not a.of_kind("checkpoint")
    cp = a.checkpoint()
    assert cp["kind"] == "checkpoint" and cp["count"] == 3 and a.verify()[0]


def test_head_and_helpers():
    a = AuditLog()
    assert a.head == AuditLog.GENESIS
    a.append("x", id="i1")
    a.append("y", incident_id="i1")
    a.append("z", id="i2")
    assert a.head == a.entries[-1]["hash"]
    assert [e["kind"] for e in a.for_incident("i1")] == ["x", "y"]
    assert len(a.of_kind("z")) == 1


# ---- tamper tests: one per attack ---------------------------------------------------------------------


def test_tamper_edit_content():
    a = build()
    a.entries[6]["n"] = 666
    r = a.verify_full()
    assert not r.ok and r.first_bad_seq == 6 and "content altered" in r.problems[0]


def test_tamper_delete_entry():
    a = build()
    del a.entries[7]
    r = a.verify_full()
    assert not r.ok and r.first_bad_seq == 7 and "out of order" in r.problems[0]


def test_tamper_reorder_entries():
    a = build()
    a.entries[3], a.entries[4] = a.entries[4], a.entries[3]
    r = a.verify_full()
    assert not r.ok and r.first_bad_seq == 3


def test_tamper_insert_forged_entry():
    a = build()
    forged = copy.deepcopy(a.entries[2])
    forged["n"] = 1234
    a.entries.insert(3, forged)
    assert not a.verify()[0]


def test_tamper_swap_prev_pointer():
    a = build()
    a.entries[5]["prev"] = "f" * 64
    r = a.verify_full()
    assert r.first_bad_seq == 5 and "prev hash mismatch" in r.problems[0]


def test_tamper_checkpoint_root_and_block_bounds():
    a = build()
    cp = next(e for e in a.entries if e["kind"] == "checkpoint")
    cp["merkle_root"] = "0" * 63 + "1"
    r = a.verify_full()
    assert not r.ok and r.first_bad_seq == cp["seq"]  # hash covers the root, so the entry itself no longer matches
    b = build()
    cp2 = [e for e in b.entries if e["kind"] == "checkpoint"][1]
    cp2["block_start"] = 0
    assert not b.verify()[0]


def test_full_rewrite_without_key_passes_plain_chain_but_not_anchor():
    anchor = MemoryAnchor()
    a = build(20, anchor=anchor)
    a.entries[6]["n"] = 666  # attacker edits history...
    forged = rewrite(a.entries)  # ...and recomputes every hash and Merkle root
    assert forged.verify()[0], "a hash chain alone cannot detect a full rewrite (documented limitation)"
    r = forged.verify_full(anchors=anchor.roots)
    assert not r.ok and "differs from external anchor" in r.problems[0]


def test_truncation_is_detected_only_with_an_external_anchor():
    anchor = MemoryAnchor()
    a = build(20, anchor=anchor)
    a.entries = a.entries[:10]
    assert a.verify()[0]  # internally consistent prefix
    r = a.verify_full(anchors=anchor.roots)
    assert not r.ok and "log truncated" in r.problems[0]


def test_anchors_pass_on_an_intact_log():
    anchor = MemoryAnchor()
    a = build(20, anchor=anchor)
    assert len(anchor.roots) == 5 and a.verify_full(anchors=anchor.roots).ok


# ---- HMAC signatures ------------------------------------------------------------------------------------


def test_signed_log_verifies_and_reports_signed():
    a = build(key="s3cret")
    assert all("sig" in e for e in a.entries)
    r = a.verify_full()
    assert r.ok and r.signed


def test_full_rewrite_is_caught_by_signatures():
    a = build(key="s3cret")
    a.entries[6]["n"] = 666
    forged = rewrite(a.entries)  # attacker has no key -> unsigned chain
    forged.key = b"s3cret"  # the verifier does have it
    r = forged.verify_full()
    assert not r.ok and "unsigned" in r.problems[0]


def test_stripping_signatures_does_not_downgrade_verification():
    a = build(key="s3cret")
    for e in a.entries:
        e.pop("sig")
    assert not a.verify()[0] and a.verify_full().first_bad_seq == 0


def test_wrong_key_and_forged_signature_fail():
    a = build(key="s3cret")
    a.key = b"other"
    r = a.verify_full()
    assert not r.ok and "bad signature" in r.problems[0] and r.first_bad_seq == 0
    b = build(key="s3cret")
    b.entries[4]["sig"] = "0" * 64
    assert b.verify_full().first_bad_seq == 4


def test_require_signatures_without_a_key_fails_and_unchecked_signatures_are_reported():
    a = build(key="k")
    plain = AuditLog(checkpoint_every=4)
    plain.entries = copy.deepcopy(a.entries)
    r = plain.verify_full()
    assert r.ok and not r.signed and r.unchecked_signatures == len(a.entries)
    assert not plain.verify_full(require_signatures=True).ok
    assert "signatures required" in plain.verify_full(require_signatures=True).problems[0]


def test_key_from_environment(monkeypatch):
    monkeypatch.setenv(ENV_KEY, "envkey")
    a = build(5)
    assert a.key == b"envkey" and all("sig" in e for e in a.entries) and a.verify_full().signed
    assert AuditLog(key=b"explicit").key == b"explicit"


# ---- persistence ----------------------------------------------------------------------------------------


def test_persisted_log_resumes_checkpoint_cadence_and_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    a = build(10, every=4, path=p)
    b = AuditLog(p, checkpoint_every=4)
    assert b.head == a.head
    b.append("more")
    b.append("more")
    b.append("more")
    c = AuditLog.load(p)
    assert c.verify_full().ok and len(c.entries) == len(b.entries)
    assert c.checkpoint_every == 0


def test_persisted_log_tamper_on_disk_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    build(10, path=p, key="k")
    lines = p.read_text().splitlines()
    rec = json.loads(lines[3])
    rec["n"] = 999
    lines[3] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    r = AuditLog.load(p, key="k").verify_full()
    assert not r.ok and r.first_bad_seq == 3
    p.write_text("\n".join(lines[:3] + lines[4:]) + "\n")
    assert not AuditLog.load(p, key="k").verify()[0]


def test_file_anchor_roundtrip(tmp_path):
    fa = FileAnchor(tmp_path / "anchors.txt")
    assert fa.read() == {}
    a = build(12, anchor=fa)
    roots = fa.read()
    assert len(roots) == 3 and a.verify_full(anchors=roots).ok
    (tmp_path / "anchors.txt").write_text((tmp_path / "anchors.txt").read_text() + "\n")
    assert fa.read() == roots  # blank lines ignored


# ---- replay ---------------------------------------------------------------------------------------------


def test_replay_reconstructs_the_run_from_the_log_alone():
    f = Fleet(30, seed=2)
    h = next(x.id for x in f.hosts.values() if x.role == "worker")
    f.inject(h, "disk_failing")
    orch = Orchestrator(f, approver=approve_all)
    orch.run(25)
    st = replay(orch.audit.entries)
    assert isinstance(st, ReplayState)
    assert [(e["tick"], e["runbook"], e["host"]) for e in st.executed] == orch.executed
    assert st.drained == {x.id for x in f.hosts.values() if x.drained}
    assert h in st.ticketed
    inc = next(iter(st.incidents.values()))
    assert inc["status"] == "resolved" and inc["executed"] == orch.records[inc["id"]].executed
    assert inc["severity"] and inc["root_cause"] == "disk_failing"
    (req,) = st.approvals.values()
    assert req["status"] == "approved" and len(req["votes"]) == 2 and req["required"] == 2
    assert st.runbook_counts["replace_disk"] == 1
    assert st.last_tick == max(e["tick"] for e in orch.audit.entries if "tick" in e)
    assert all(v["ok"] for v in st.verifications) and st.denied == []
    d = st.to_dict()
    assert d["drained"] == sorted(st.drained) and d["executed"][0]["runbook"] == "drain_host"


def test_replay_tracks_undrain_denials_pages_and_scenario_events():
    entries = [
        {"kind": "scenario_event", "tick": 1, "type": "inject", "host": "h1"},
        {"kind": "incident", "id": "i1", "tick": 2, "host": "h1", "signal": "x"},
        {"kind": "policy", "id": "i1", "tick": 2, "runbook": "reboot_host", "host": "h1", "decision": "DENY",
         "code": "DENY_FREEZE_WINDOW"},
        {"kind": "policy", "id": "i1", "tick": 2, "runbook": "replace_disk", "host": "h1", "decision": "DENY",
         "code": "DENY_PRECONDITION_FAILED", "provisional": True},
        {"kind": "executed", "id": "i1", "tick": 3, "runbook": "drain_host", "host": "h1", "hosts": ["h1"],
         "changes": ["h1.drained: False -> True", "h1.ticketed: False -> True"]},
        {"kind": "executed", "id": "i1", "tick": 4, "runbook": "undrain_host", "host": "h1", "hosts": ["h1"],
         "changes": ["h1.drained: True -> False"]},
        {"kind": "page", "tick": 5, "id": "i1", "reason": "r"},
        {"kind": "closed", "tick": 6, "id": "i1", "status": "contained"},
        {"kind": "checkpoint", "tick": 6},
    ]
    st = replay(entries)
    assert st.drained == set() and st.ticketed == {"h1"}
    assert st.denied == [{"incident": "i1", "runbook": "reboot_host", "host": "h1", "code": "DENY_FREEZE_WINDOW"}]
    assert st.decisions == {"DENY_FREEZE_WINDOW": 1, "DENY_PRECONDITION_FAILED": 1}
    assert st.pages[0]["reason"] == "r" and st.incidents["i1"]["status"] == "contained"
    assert st.scenario_events == [{"tick": 1, "type": "inject", "host": "h1"}] and st.checkpoints == 1
    assert st.incidents["i1"]["denied"] == ["reboot_host@h1"]
