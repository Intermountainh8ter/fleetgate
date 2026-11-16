"""Degenerate callers (empty, constant, replay) against the real gate."""
import json
import random

import pytest

from fleetgate.audit import AuditLog
from fleetgate.cli import main as cli_main
from fleetgate.degenerate_caller import PROPOSALS, run_caller, simulate
from fleetgate.split_caller import _fleet, admissible_runbooks


def test_rates_and_audit():
    a = simulate(3, 10)
    d = a["degenerate"]
    assert d["empty_caller_admit_rate"] == 0.0
    assert d["constant_caller_admit_rate"] <= 0.25
    assert d["replay_caller_admit_rate"] <= 0.25
    assert d["constant_caller_admit_rate"] < d["honest_caller_admit_rate"]
    assert set(d["verdict_codes_by_caller"]["empty"]) and len(d["verdict_codes_by_caller"]["empty"]) >= 1
    assert all(a["verify_full_ok"].values())
    assert all(a["entries_equal_decisions"].values())
    assert a == simulate(3, 10)


def test_empty_all_denied():
    log = AuditLog()
    hosts = list(_fleet().hosts)
    adm, cnt, logged = run_caller("empty", admissible_runbooks(), hosts, 0, log, random.Random(1))
    assert (adm, cnt, logged) == (0, PROPOSALS, PROPOSALS)


def test_unknown_caller():
    with pytest.raises(ValueError):
        run_caller("x", [], [], 0, AuditLog(), random.Random(1))


def test_cli_writes_json(tmp_path):
    out = tmp_path / "r.json"
    assert cli_main(["degenerate-caller", "--seeds", "7", "--rounds", "3", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert "started_at" in data["provenance"]
    assert data["degenerate"]["constant_caller_admit_rate"] <= 0.25
