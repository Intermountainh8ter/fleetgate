import json

from fleetgate.audit import AuditLog


def test_chain_verifies():
    a = AuditLog()
    for i in range(5):
        a.append("evt", n=i)
    assert a.verify() == (True, None)


def test_tamper_detected_at_first_bad_entry():
    a = AuditLog()
    for i in range(5):
        a.append("evt", n=i)
    a.entries[2]["n"] = 999
    assert a.verify() == (False, 2)


def test_deletion_detected():
    a = AuditLog()
    for i in range(5):
        a.append("evt", n=i)
    del a.entries[1]
    assert a.verify()[0] is False


def test_persistence_roundtrip(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = AuditLog(p)
    a.append("x", v=1)
    a.append("y", v=2)
    b = AuditLog(p)
    assert b.verify()[0] and len(b.entries) == 2
    b.append("z", v=3)
    assert AuditLog(p).verify()[0]
    first = json.loads(p.read_text().splitlines()[0])
    assert first["prev"] == AuditLog.GENESIS
