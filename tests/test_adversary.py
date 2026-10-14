"""The adversary module: generators are hostile, and check_invariants really detects each class of violation."""
import copy
import random

import pytest
from helpers import first_host

from fleetgate import Fleet, Orchestrator
from fleetgate.adversary import ALLOWED_WITHOUT_APPROVAL, FuzzPlanner, check_invariants, junk, lookalike
from fleetgate.agents import Proposal
from fleetgate.orchestrator import approve_all
from fleetgate.runbooks import CATALOG


def test_lookalikes_are_never_catalogue_ids():
    rng = random.Random(0)
    for name in CATALOG:
        for _ in range(50):
            v = lookalike(name, rng)
            assert v != name or False  # every variant differs from its original...
            assert v not in CATALOG or v == name  # ...and none collides with another real runbook
    assert not any(lookalike(n, rng) in CATALOG for n in CATALOG for _ in range(20))


def test_junk_is_json_shaped_and_varied():
    rng = random.Random(1)
    kinds = {type(junk(rng)).__name__ for _ in range(400)}
    assert {"NoneType", "int", "bool", "str", "list", "dict"} <= kinds


def test_fuzz_planner_is_deterministic_and_reaches_for_destructive_chains():
    f = Fleet(30, seed=1)
    a = FuzzPlanner(f, 5).plan(None, None)
    b = FuzzPlanner(f, 5).plan(None, None)
    assert [repr(x) for x in a] == [repr(x) for x in b]
    assert any(isinstance(p, Proposal) and p.rationale == "chain" for p in a)
    assert FuzzPlanner(f, 5, chain_prob=0.0).plan(None, None)[0] != a[0]
    assert len(FuzzPlanner(f, 5, size=50, chain_prob=0.0).plan(None, None)) == 50


def run(planner_steps=("drain_host", "open_ticket", "replace_disk"), approver=approve_all, ticks=25):
    class Chain:
        def plan(self, inc, tri):
            return [Proposal(r, inc.host, "") for r in planner_steps]

    f = Fleet(30, seed=2)
    f.inject(first_host(f, "worker"), "disk_failing")
    o = Orchestrator(f, planner=Chain(), approver=approver)
    o.run(ticks)
    return o


def test_clean_run_has_no_violations():
    o = run()
    assert o.executed and check_invariants(o) == []


def tamper(o, fn, verify_chain=False):
    o2 = copy.copy(o)
    o2.audit = copy.copy(o.audit)
    o2.audit.entries = copy.deepcopy(o.audit.entries)
    fn(o2)
    return check_invariants(o2, verify_chain=verify_chain)


def test_each_class_of_violation_is_detected():
    o = run()
    execs = [e for e in o.audit.entries if e["kind"] == "executed"]
    destructive = next(e for e in execs if e["runbook"] == "replace_disk")

    def no_request(o2):
        next(e for e in o2.audit.entries if e["seq"] == destructive["seq"])["request_id"] = None

    assert any("executed without a prior approval" in x for x in tamper(o, no_request))

    def unknown(o2):
        execs2 = [e for e in o2.audit.entries if e["kind"] == "executed"]
        execs2[0]["runbook"] = "rm_rf"

    assert any("unknown runbook executed" in x for x in tamper(o, unknown))

    def denylisted(o2):
        o2.policy.cfg.deny_list.add("drain_host")

    assert any("deny-listed runbook executed" in x for x in tamper(o, denylisted))

    def budget(o2):
        o2.policy.cfg.max_actions_per_tick = 0

    assert any("per-tick budget exceeded" in x for x in tamper(o, budget))

    def cap(o2):
        o2.policy.cfg.max_drained_fraction = 0.0

    assert any("drained fraction" in x for x in tamper(o, cap))

    def freeze(o2):
        o2.policy.cfg.freeze_windows = [{"start": 0, "end": 10**6, "allow_tiers": []}]

    assert any("change freeze violated" in x for x in tamper(o, freeze))

    def drop_drain(o2):
        for e in o2.audit.entries:
            if e["kind"] == "executed" and e["runbook"] == "drain_host":
                e["changes"] = []

    v = tamper(o, drop_drain)
    assert any("precondition host_drained violated" in x for x in v)

    def break_chain(o2):
        o2.audit.entries[3]["tick"] = 999

    assert not any("hash chain" in x for x in tamper(o, break_chain))  # chain check can be switched off...
    assert any("hash chain" in x for x in tamper(o, break_chain, verify_chain=True))


def test_not_drained_precondition_and_ticket_precondition_are_checked():
    o = run(("drain_host", "open_ticket", "replace_disk", "undrain_host"))
    assert check_invariants(o) == []

    def drop_ticket(o2):
        for e in o2.audit.entries:
            if e["kind"] == "executed" and e["runbook"] == "open_ticket":
                e["changes"] = []

    assert any("ticket_open violated" in x for x in tamper(o, drop_ticket))
    assert "ALLOW_REVERSIBLE" in ALLOWED_WITHOUT_APPROVAL


@pytest.mark.parametrize("gate", ["ALLOW_REVERSIBLE", "ALLOW_CANARY", "DENY_COOLDOWN", None])
def test_destructive_without_request_is_never_excused_by_any_gate_code(gate):
    o = run()

    def fake(o2):
        for e in o2.audit.entries:
            if e["kind"] == "executed" and e["runbook"] == "replace_disk":
                e["request_id"], e["gate"] = None, gate

    assert any("executed without a prior approval" in x for x in tamper(o, fake))
