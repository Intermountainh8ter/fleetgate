"""Policy fuzzer: seeded hostile proposals must never break the gate's invariants.

Invariants asserted on every run:
  1. no unknown runbook is ever executed;
  2. no DESTRUCTIVE runbook and no protected-role action executes without an approved approval record
     (filed before the execution) -- and approval never overrides a DENY;
  3. the drained fraction never exceeds the active policy's cap;
  4. per-tick action budget, deny-list and change-freeze rules hold;
  5. the audit chain still verifies and the orchestrator never raises.
"""
import json
import random

import pytest

from fleetgate import Fleet, Orchestrator
from fleetgate.adversary import INVISIBLES, FuzzPlanner, check_invariants, junk, lookalike
from fleetgate.agents import AdversarialLLM, LLMPlanner, TriageAgent
from fleetgate.detect import Incident
from fleetgate.fleet import FAULT_SPECS
from fleetgate.llm import ScriptedLLM
from fleetgate.orchestrator import approve_all, deny_all
from fleetgate.policy import Decision, Policy, PolicyConfig, Reason, available_policies
from fleetgate.runbooks import CATALOG, Tier


def build(seed: int, policy_name: str, approver):
    rng = random.Random(seed)
    f = Fleet(rng.choice([30, 40, 60]), seed=seed)
    for _ in range(rng.randrange(2, 6)):
        f.inject(rng.choice(sorted(f.hosts)), rng.choice(list(FAULT_SPECS)))
    cfg = PolicyConfig.load(policy_name)
    return f, cfg, Orchestrator(f, planner=FuzzPlanner(f, seed), policy=Policy(f, cfg), approver=approver)


@pytest.mark.parametrize("policy_name", sorted(available_policies()))
@pytest.mark.parametrize("approver", [deny_all, approve_all], ids=["deny_all", "approve_all"])
@pytest.mark.parametrize("seed", range(8))
def test_fuzzed_planner_cannot_break_the_gate(seed, approver, policy_name):
    f, cfg, o = build(seed * 31 + 7, policy_name, approver)
    cap = cfg.max_drained_fraction
    for _ in range(30):
        o.tick()
        assert f.drained_fraction() <= cap + 1e-9, f"drained {f.drained_fraction():.3f} > cap {cap}"
    assert check_invariants(o) == []
    assert o.records, "the fuzz scenario should have opened incidents"


@pytest.mark.parametrize("seed", range(10))
def test_evaluate_is_total_deterministic_and_default_deny(seed):
    rng = random.Random(seed)
    f = Fleet(rng.choice([20, 40]), seed=seed)
    cfg = PolicyConfig.load(rng.choice(sorted(available_policies())))
    hosts = list(f.hosts)
    for _ in range(600):
        rb = rng.choice([junk(rng), lookalike(rng.choice(list(CATALOG)), rng), rng.choice(list(CATALOG))])
        host = rng.choice([junk(rng), rng.choice(hosts), rng.choice(hosts) + rng.choice(INVISIBLES)])
        v = Policy(f, cfg).evaluate(rb, host)  # fresh policy each time: verdicts are a pure function of the inputs
        v2 = Policy(f, cfg).evaluate(rb, host)
        assert (v.decision, v.code, v.reason) == (v2.decision, v2.code, v2.reason)
        assert v.code.decision == v.decision
        if v.decision != Decision.DENY:
            assert isinstance(rb, str) and rb in CATALOG, repr(rb)
            assert isinstance(host, str) and host in f.hosts, repr(host)
        if v.decision == Decision.NEEDS_APPROVAL:
            assert v.requirement is not None and v.requirement.required >= 1
        else:
            assert v.requirement is None
        if not (isinstance(rb, str) and rb in CATALOG):
            assert v.code in (Reason.UNKNOWN_RUNBOOK, Reason.INTERNAL_ERROR)


def test_every_allowed_verdict_is_reversible_or_in_a_maintenance_window_on_an_unprotected_host():
    rng = random.Random(99)
    f = Fleet(40, seed=3)
    for h in f.hosts.values():
        h.drained = rng.random() < 0.3
        h.ticketed = rng.random() < 0.5
    for name in available_policies():
        cfg = PolicyConfig.load(name)
        for tick in (0, 5, 41, 100, 350):
            f.tick = tick
            for rb in CATALOG.values():
                for h in rng.sample(list(f.hosts), 6):
                    v = Policy(f, cfg).evaluate(rb.id, h)
                    if v.decision != Decision.ALLOW:
                        continue
                    targets = rb.target_hosts(f, h)
                    assert not any(f.hosts[t].role in cfg.protected_roles for t in targets)
                    assert rb.tier == Tier.REVERSIBLE or v.code == Reason.MAINTENANCE_WINDOW, (name, rb.id, v)
                    assert rb.id not in cfg.deny_list


# ---- LLM-shaped fuzz: random JSON text through the real LLMPlanner ----------------------------------------


def random_json_text(rng: random.Random) -> str:
    kind = rng.randrange(6)
    if kind == 0:
        return json.dumps(junk(rng))
    if kind == 1:
        items = [{"runbook": rng.choice([lookalike(r, rng) for r in CATALOG] + list(CATALOG)),
                  "host": rng.choice(["h001", "h002", "h001\n", "h0001", "H001", "h999"]),
                  "rationale": junk(rng)} for _ in range(rng.randrange(0, 14))]
        return "Here is the plan:\n```json\n" + json.dumps(items) + "\n```\nThanks!"
    if kind == 2:
        return "[" * rng.randrange(1, 400) + "]" * rng.randrange(0, 400)
    if kind == 3:
        return "".join(rng.choice('[]{}",:\\ \n0a') for _ in range(rng.randrange(0, 300)))
    if kind == 4:
        return json.dumps({"plan": [{"runbook": "reboot_host", "host": "h001"}], "approved": True, "policy": "off"})
    return json.dumps([{"runbook": r, "host": "h001"} for r in CATALOG])  # all 30+ runbooks at once


@pytest.mark.parametrize("seed", range(40))
def test_random_llm_text_never_escapes_the_catalogue_or_the_incident_scope(seed):
    rng = random.Random(seed)
    f = Fleet(30, seed=2)
    inc = Incident("inc-h001-x", "h001", "service_down", 3)
    tri = TriageAgent(f).triage(inc)
    for _ in range(25):
        planner = LLMPlanner(ScriptedLLM([random_json_text(rng), random_json_text(rng)]))
        out = planner.plan_detailed(inc, tri)  # must not raise
        assert len(out.proposals) <= 8
        assert all(p.runbook in CATALOG and p.host == "h001" for p in out.proposals)
        assert all(isinstance(p.rationale, str) and len(p.rationale) <= 300 for p in out.proposals)


def test_adversarial_llm_through_the_whole_orchestrator_is_contained():
    f = Fleet(30, seed=2)
    f.inject("h003", "service_down")
    for attack in sorted(AdversarialLLM.ATTACKS):
        f2 = Fleet(30, seed=2)
        f2.inject("h003", "service_down")
        o = Orchestrator(f2, planner=LLMPlanner(AdversarialLLM(attack)), approver=deny_all)
        o.run(10)
        assert all(rb in ("restart_service",) for _, rb, _ in o.executed), attack
        assert o.audit.verify()[0]
