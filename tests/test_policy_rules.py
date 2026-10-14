"""Policy rules loaded from JSON: windows, quotas, rate limits, canary-first, deny-list, capacity floors, codes."""
import copy
import json

import pytest

from fleetgate.fleet import Fleet
from fleetgate.policy import POLICY_DIR, ApprovalRequirement, Decision, Policy, PolicyConfig, Reason, available_policies
from fleetgate.schema import SchemaError


def make_fleet(n=40, seed=1, db_primary=0, **kw):
    """n hosts, everything a worker except the first `db_primary` hosts (protected)."""
    f = Fleet(n, seed=seed, **kw)
    for i, h in enumerate(f.hosts.values()):
        h.role = "db-primary" if i < db_primary else "worker"
    return f, list(f.hosts)


def cfg(**over):
    base = PolicyConfig.load("default").to_dict()
    base.update(over)
    return PolicyConfig.from_dict(base)


def gate(f, **over):
    """Policy with canary-first OFF unless the test passes its own canary block (keeps rule tests independent)."""
    over.setdefault("canary", {"enabled": False})
    return Policy(f, cfg(**over))


def prep_destructive(f, h):
    f.hosts[h].drained = True
    f.hosts[h].ticketed = True


# ---- configuration --------------------------------------------------------------------------------------


def test_bundled_policies_load_and_roundtrip():
    names = available_policies()
    assert {"default", "strict", "permissive", "freeze", "canary"} <= set(names)
    for n in names:
        c = PolicyConfig.load(n)
        assert c.name == n
        assert PolicyConfig.from_dict(c.to_dict()).to_dict() == c.to_dict()
    assert (POLICY_DIR / "default.json").exists()


def test_load_from_path_and_unknown_name(tmp_path):
    p = tmp_path / "mine.json"
    p.write_text(json.dumps({"name": "mine", "max_drained_fraction": 0.2}))
    c = PolicyConfig.load(p)
    assert c.name == "mine" and c.max_drained_fraction == 0.2 and c.cooldown_ticks == 5  # unspecified -> defaults
    with pytest.raises(FileNotFoundError, match="bundled: "):
        PolicyConfig.load("does-not-exist")


@pytest.mark.parametrize("patch,needle", [
    ({"name": "Bad Name"}, "does not match"),
    ({"max_drained_fraction": 1.5}, "maximum"),
    ({"cooldown_ticks": -1}, "minimum"),
    ({"mystery": 1}, "unexpected property"),
    ({"freeze_windows": [{"start": 5, "end": 5}]}, "end > start"),
    ({"maintenance_windows": [{"start": 9, "end": 3}]}, "end > start"),
    ({"freeze_windows": [{"start": 0}]}, "missing required"),
    ({"approvals": {"DESTRUCTIVE": {"required": 3, "roles": ["a", "b"]}}}, "need 3 of 2"),
    ({"approvals": {"DESTRUCTIVE": {"required": 1, "roles": ["a", "a"]}}}, "duplicate"),
    ({"approvals": {"EVERYTHING": {"required": 1, "roles": ["a"]}}}, "unexpected property"),
    ({"quotas": {"per_role": {"worker": -1}}}, "minimum"),
    ({"rate_limits": {"reboot_host": {"max": 1}}}, "missing required"),
    ({"canary": {"fleet_fraction": 2}}, "maximum"),
])
def test_invalid_policy_documents_are_rejected(patch, needle):
    doc = copy.deepcopy(PolicyConfig.load("default").to_dict())
    doc.update(patch)
    with pytest.raises((SchemaError, ValueError)) as ei:
        PolicyConfig.from_dict(doc)
    assert needle in str(ei.value)


def test_explain_mentions_every_active_rule():
    text = "\n".join(Policy(Fleet(10), PolicyConfig.load("strict")).explain())
    for needle in ("protected roles", "deny-list", "approvals DESTRUCTIVE: 2 of", "rate limits: reboot_host 1/20t",
                   "quotas per 24 ticks", "canary-first", "escalation: page after 2", "capacity floors"):
        assert needle in text
    fz = "\n".join(Policy(Fleet(10), PolicyConfig.load("freeze")).explain())
    assert "freeze 'release freeze'" in fz and "maintenance 'weekly dc1 window'" in fz


# ---- reason codes ---------------------------------------------------------------------------------------


def test_reason_prefix_matches_decision_family():
    for r in Reason:
        want = {"DENY": Decision.DENY, "APPROVAL": Decision.NEEDS_APPROVAL, "ALLOW": Decision.ALLOW}[
            r.value.split("_")[0]]
        assert r.decision == want, r
    assert len({r.value for r in Reason}) == len(Reason)


def test_verdict_is_machine_readable():
    f, ids = make_fleet()
    v = Policy(f).evaluate("format_c", ids[1])
    d = v.to_dict()
    assert d == {"decision": "DENY", "code": "DENY_UNKNOWN_RUNBOOK", "reason": "unknown runbook 'format_c'",
                 "requirement": None}
    prep_destructive(f, ids[1])
    v = Policy(f).evaluate("replace_disk", ids[1])
    assert v.to_dict()["requirement"] == {
        "required": 2, "roles": ["sre-lead", "dc-ops"], "code": "APPROVAL_DESTRUCTIVE_TIER",
        "pools": [{"required": 2, "roles": ["sre-lead", "dc-ops"]}]}


@pytest.mark.parametrize("name", ["drain_host ", " drain_host", "Drain_Host", "drain-host", "draın_host",
                                  "drаin_host", "drain_host​", "drain_host\n", "drain_host\x00", "",
                                  "../drain_host", "drain_host;reboot_host", "DROP TABLE"])
def test_typosquats_and_lookalikes_are_unknown_runbooks(name):
    f, ids = make_fleet()
    v = Policy(f).evaluate(name, ids[1])
    assert v.decision == Decision.DENY and v.code == Reason.UNKNOWN_RUNBOOK


@pytest.mark.parametrize("host", ["h999", "H001", "h001 ", "h0001", "*", "all", "", "h001;h002", "../h001"])
def test_spoofed_hosts_are_unknown_hosts(host):
    f, _ = make_fleet()
    assert Policy(f).evaluate("restart_service", host).code == Reason.UNKNOWN_HOST


def test_unhashable_or_non_string_input_fails_closed():
    f, ids = make_fleet()
    p = Policy(f)
    for bad in ([], {}, None, 7, ("a",)):
        v = p.evaluate(bad, ids[1])
        assert v.decision == Decision.DENY
        v = p.evaluate("restart_service", bad)
        assert v.decision == Decision.DENY
    assert p.evaluate([], ids[1]).code == Reason.INTERNAL_ERROR
    assert p.decisions["DENY_INTERNAL_ERROR"] >= 1


def test_every_decision_is_counted_by_code():
    f, ids = make_fleet()
    p = gate(f)
    p.evaluate("restart_service", ids[1])
    p.evaluate("restart_service", ids[2])
    p.evaluate("nope", ids[2])
    assert p.decisions == {"ALLOW_REVERSIBLE": 2, "DENY_UNKNOWN_RUNBOOK": 1}


# ---- deny-list, preconditions, approvals --------------------------------------------------------------


def test_deny_list_beats_everything_including_satisfied_preconditions():
    f, ids = make_fleet()
    prep_destructive(f, ids[1])
    v = Policy(f).evaluate("decommission_host", ids[1])
    assert v.decision == Decision.DENY and v.code == Reason.DENY_LIST
    strict = Policy(f, PolicyConfig.load("strict"))
    assert strict.evaluate("reimage_host", ids[1]).code == Reason.DENY_LIST
    assert gate(f, deny_list=["restart_service"]).evaluate("restart_service", ids[2]).code == Reason.DENY_LIST


def test_preconditions_gate_before_approval_is_even_asked():
    f, ids = make_fleet()
    v = Policy(f).evaluate("replace_disk", ids[1])
    assert v.code == Reason.PRECONDITION_FAILED and "host_drained" in v.reason and "ticket_open" in v.reason
    f.hosts[ids[1]].drained = True
    assert "ticket_open" in Policy(f).evaluate("replace_disk", ids[1]).reason
    f.hosts[ids[1]].ticketed = True
    assert Policy(f).evaluate("replace_disk", ids[1]).decision == Decision.NEEDS_APPROVAL


def test_tiers_map_to_decisions_and_requirements():
    f, ids = make_fleet(db_primary=1)
    f.hosts[ids[2]].drained = True
    p = gate(f)
    v = p.evaluate("reboot_host", ids[2])  # DISRUPTIVE on a drained worker
    assert v.decision == Decision.NEEDS_APPROVAL and v.code == Reason.DISRUPTIVE_TIER
    assert v.requirement == ApprovalRequirement(1, ("sre", "sre-lead"), Reason.DISRUPTIVE_TIER)
    prep_destructive(f, ids[3])
    v = p.evaluate("replace_disk", ids[3])
    assert v.code == Reason.DESTRUCTIVE_TIER and v.requirement.required == 2
    v = p.evaluate("restart_service", ids[0])  # reversible on a protected host
    assert v.code == Reason.PROTECTED_ROLE and v.requirement.roles == ("sre-lead", "db-owner")
    assert p.evaluate("restart_service", ids[4]).code == Reason.REVERSIBLE


def test_policy_whose_stacked_requirements_can_never_be_met_is_rejected():
    doc = PolicyConfig.load("default").to_dict()
    doc["approvals"] = {"DISRUPTIVE": {"required": 1, "roles": ["sre"]},
                        "protected": {"required": 2, "roles": ["sre", "x"]}}
    with pytest.raises(ValueError, match="can never be satisfied"):
        PolicyConfig.from_dict(doc)


def test_destructive_on_protected_host_combines_requirements():
    f, ids = make_fleet(db_primary=1)
    prep_destructive(f, ids[0])
    c = cfg(approvals={"DESTRUCTIVE": {"required": 1, "roles": ["a", "b"]},
                       "protected": {"required": 2, "roles": ["c", "d"]}}, max_drained_fraction=1.0)
    v = Policy(f, c).evaluate("replace_disk", ids[0])
    assert v.code == Reason.DESTRUCTIVE_TIER
    # both pools must be filled, by different people: 1 of {a,b} AND 2 of {c,d}
    assert v.requirement.required == 3 and v.requirement.roles == ("a", "b", "c", "d")
    assert v.requirement.pools == ((1, ("a", "b")), (2, ("c", "d")))


# ---- cooldown, tick budget, rate limits, quotas ---------------------------------------------------------


def test_cooldown_and_tick_budget_codes():
    f, ids = make_fleet()
    p = gate(f, max_actions_per_tick=2, cooldown_ticks=5)
    p.record("restart_service", ids[1])
    assert p.evaluate("restart_service", ids[1]).code == Reason.COOLDOWN
    p.record("restart_service", ids[2])
    assert p.evaluate("restart_service", ids[3]).code == Reason.TICK_BUDGET
    f.tick += 1
    assert p.evaluate("restart_service", ids[3]).code == Reason.REVERSIBLE
    f.tick += 5
    assert p.evaluate("restart_service", ids[1]).code == Reason.REVERSIBLE


def test_rate_limit_counts_executions_in_a_sliding_window():
    f, ids = make_fleet()
    p = gate(f, rate_limits={"restart_service": {"max": 2, "window_ticks": 10}}, max_actions_per_tick=99)
    for h in ids[1:3]:
        p.record("restart_service", h)
    v = p.evaluate("restart_service", ids[5])
    assert v.code == Reason.RATE_LIMIT and "2x in 10 ticks" in v.reason
    f.tick += 10
    assert p.evaluate("restart_service", ids[5]).code == Reason.REVERSIBLE


def test_role_quota_and_dc_quota():
    f, ids = make_fleet(db_primary=3)
    p = gate(f, quotas={"window_ticks": 24, "per_role": {"db-primary": 2}, "per_dc": {}}, max_actions_per_tick=99)
    p.record("open_ticket", ids[0])
    p.record("open_ticket", ids[1])
    assert p.evaluate("open_ticket", ids[2]).code == Reason.QUOTA_ROLE
    f.tick += 24
    assert p.evaluate("open_ticket", ids[2]).code == Reason.PROTECTED_ROLE  # window passed; protected approval next
    f2, ids2 = make_fleet(n=60, dcs=2)
    dc1 = f2.topology.dc_of(ids2[1])
    p2 = gate(f2, quotas={"window_ticks": 24, "per_role": {}, "per_dc": {dc1: 1}}, max_actions_per_tick=99)
    p2.record("open_ticket", ids2[1])
    v = p2.evaluate("open_ticket", ids2[2])
    assert v.code == Reason.QUOTA_DC and dc1 in v.reason
    other = next(h for h in ids2 if f2.topology.dc_of(h) != dc1)
    assert p2.evaluate("open_ticket", other).decision == Decision.ALLOW


# ---- blast radius and capacity floors -----------------------------------------------------------------


def test_blast_radius_counts_drained_and_decommissioned():
    f, ids = make_fleet(n=20)
    p = gate(f, max_actions_per_tick=99)
    f.hosts[ids[1]].decommissioned = True
    f.hosts[ids[2]].drained = True
    v = p.evaluate("drain_host", ids[3])
    assert v.code == Reason.BLAST_RADIUS  # 2 of 20 already gone = the 10% cap
    p2 = gate(f, max_actions_per_tick=99, max_drained_fraction=0.15)
    assert p2.evaluate("drain_host", ids[3]).decision == Decision.ALLOW


def test_rack_scope_runbook_is_judged_by_everything_it_touches():
    f, ids = make_fleet(n=100, db_primary=1)
    f.hosts[ids[55]].role = "db-primary"  # a second primary elsewhere keeps the capacity floor out of the way
    rack0 = f.topology.rack_of(ids[0])
    target = next(h for h in rack0.hosts if f.hosts[h].role == "worker")
    p = gate(f, max_drained_fraction=0.10, max_actions_per_tick=99)
    v = p.evaluate("migrate_workloads", target)
    # draining the rack (10 hosts of 100) fits the cap, but the rack contains the db-primary: protected approval
    assert v.decision == Decision.NEEDS_APPROVAL
    assert v.requirement.pools == ((1, ("sre", "sre-lead")), (1, ("sre-lead", "db-owner")))
    assert v.requirement.required == 2  # a plain sre alone can no longer approve work on the primary's rack
    p2 = gate(f, max_drained_fraction=0.05, max_actions_per_tick=99)
    assert p2.evaluate("migrate_workloads", target).code == Reason.BLAST_RADIUS
    # failing over a ToR uplink is reversible, but it also touches the protected host in that rack
    assert p.evaluate("failover_tor_uplink", target).code == Reason.PROTECTED_ROLE


def test_role_capacity_floor_protects_the_last_primary():
    f, ids = make_fleet(n=20, db_primary=1)
    p = gate(f, max_drained_fraction=1.0, max_actions_per_tick=99)
    v = p.evaluate("drain_host", ids[0])
    assert v.code == Reason.ROLE_CAPACITY_FLOOR and "would leave 0 active db-primary" in v.reason
    f.hosts[ids[1]].role = "db-primary"
    assert p.evaluate("drain_host", ids[0]).code == Reason.PROTECTED_ROLE


# ---- windows ----------------------------------------------------------------------------------------------


def test_freeze_window_denies_everything_above_its_allowed_tier():
    f, ids = make_fleet(n=20)
    f.hosts[ids[1]].drained = True
    p = Policy(f, PolicyConfig.load("freeze"))
    v = p.evaluate("reboot_host", ids[1])
    assert v.code == Reason.FREEZE_WINDOW and "DISRUPTIVE not allowed" in v.reason
    assert p.evaluate("restart_service", ids[2]).code == Reason.REVERSIBLE
    prep_destructive(f, ids[3])
    assert p.evaluate("replace_disk", ids[3]).code == Reason.FREEZE_WINDOW


def test_maintenance_window_reopens_disruptive_work_inside_a_freeze():
    f, ids = make_fleet(n=20, db_primary=1)
    f.hosts[ids[2]].drained = True
    f.hosts[ids[0]].drained = True
    p = Policy(f, PolicyConfig.load("freeze"))
    f.tick = 41  # inside [40, 48) of the weekly dc1 window
    v = p.evaluate("reboot_host", ids[2])
    assert v.decision == Decision.ALLOW and v.code == Reason.MAINTENANCE_WINDOW
    assert p.evaluate("reboot_host", ids[0]).code == Reason.FREEZE_WINDOW  # protected host: not re-opened
    prep_destructive(f, ids[3])
    assert p.evaluate("replace_disk", ids[3]).code == Reason.FREEZE_WINDOW  # destructive never re-opens
    f.tick = 48
    assert p.evaluate("reboot_host", ids[2]).code == Reason.FREEZE_WINDOW
    f.tick = 336 + 41  # weekly repeat
    assert p.evaluate("reboot_host", ids[2]).code == Reason.MAINTENANCE_WINDOW


def test_maintenance_window_is_scoped_to_its_datacenters():
    f, ids = make_fleet(n=60, dcs=2)
    in_dc2 = next(h for h in ids if f.topology.dc_of(h) == "dc2")
    in_dc1 = next(h for h in ids if f.topology.dc_of(h) == "dc1")
    for h in (in_dc1, in_dc2):
        f.hosts[h].drained = True
    p = Policy(f, PolicyConfig.load("freeze"))
    f.tick = 41
    assert p.evaluate("reboot_host", in_dc1).code == Reason.MAINTENANCE_WINDOW
    assert p.evaluate("reboot_host", in_dc2).code == Reason.FREEZE_WINDOW


def test_maintenance_window_allows_disruptive_without_approval_outside_a_freeze():
    f, ids = make_fleet(n=20)
    f.hosts[ids[1]].drained = True
    p = Policy(f, PolicyConfig.load("permissive"))
    assert p.evaluate("reboot_host", ids[1]).code == Reason.MAINTENANCE_WINDOW
    assert Policy(f).evaluate("reboot_host", ids[1]).code == Reason.DISRUPTIVE_TIER


# ---- canary-first -----------------------------------------------------------------------------------------


def test_canary_first_campaign_lifecycle():
    f, ids = make_fleet(n=40)
    p = gate(f, max_actions_per_tick=99, cooldown_ticks=0, canary={"enabled": True})
    a, b, c, d = ids[1:5]
    assert p.evaluate("restart_service", a).code == Reason.REVERSIBLE  # one host is not a campaign (needs >= 2)
    p.record("restart_service", a)
    v = p.evaluate("restart_service", b)  # second host in the window: it becomes the canary
    assert v.decision == Decision.ALLOW and v.code == Reason.CANARY
    p.record("restart_service", b)
    v = p.evaluate("restart_service", c)
    assert v.decision == Decision.DENY and v.code == Reason.CANARY_PENDING
    p.report_verification("restart_service", b, ok=True)
    assert p.evaluate("restart_service", c).code == Reason.REVERSIBLE
    assert p.evaluate("restart_service", d).code == Reason.REVERSIBLE


def test_failed_canary_freezes_the_campaign_for_its_window():
    f, ids = make_fleet(n=40)
    p = gate(f, max_actions_per_tick=99, cooldown_ticks=0, canary={"enabled": True, "window_ticks": 10})
    a, b, c = ids[1:4]
    p.evaluate("restart_service", a)
    p.evaluate("restart_service", b)
    p.record("restart_service", b)
    p.evaluate("restart_service", c)
    p.report_verification("restart_service", b, ok=False)
    assert p.evaluate("restart_service", c).code == Reason.CANARY_FAILED
    f.tick += 11
    assert p.evaluate("restart_service", c).code != Reason.CANARY_FAILED


def test_canary_ignores_verification_of_non_canary_hosts_and_unknown_campaigns():
    f, ids = make_fleet(n=40)
    p = gate(f, max_actions_per_tick=99, cooldown_ticks=0, canary={"enabled": True})
    p.report_verification("restart_service", ids[1], ok=True)  # no campaign yet: ignored
    p.evaluate("restart_service", ids[1])
    p.evaluate("restart_service", ids[2])
    p.record("restart_service", ids[2])
    p.report_verification("restart_service", ids[9], ok=True)  # not a canary: ignored
    assert p.evaluate("restart_service", ids[3]).code == Reason.CANARY_PENDING


def test_canary_can_be_disabled_and_campaign_proposals_expire():
    f, ids = make_fleet(n=40)
    p = gate(f, max_actions_per_tick=99, cooldown_ticks=0, canary={"enabled": False})
    for h in ids[1:8]:
        assert p.evaluate("restart_service", h).code == Reason.REVERSIBLE
        p.record("restart_service", h)
    p2 = gate(f, max_actions_per_tick=99, cooldown_ticks=0, canary={"enabled": True, "window_ticks": 5})
    p2.evaluate("restart_service", ids[1])
    f.tick += 6  # the first proposal aged out of the window: the next host is again the only one
    assert p2.evaluate("restart_service", ids[2]).code == Reason.REVERSIBLE


def test_a_flood_of_proposals_counts_toward_the_campaign_even_when_they_fail_other_checks():
    f, ids = make_fleet(n=40)
    p = gate(f, max_actions_per_tick=0, cooldown_ticks=0, canary={"enabled": True})
    for h in ids[1:6]:
        assert p.evaluate("restart_service", h).code == Reason.TICK_BUDGET
    p.cfg.max_actions_per_tick = 99
    assert p.evaluate("restart_service", ids[7]).code == Reason.CANARY  # first canary slot is offered
    p.record("restart_service", ids[7])
    assert p.evaluate("restart_service", ids[8]).code == Reason.CANARY_PENDING


def test_every_reason_code_has_a_meaning_and_a_fix():
    from fleetgate.policy import REASON_GUIDE

    assert set(REASON_GUIDE) == set(Reason)
    for code, (meaning, fix) in REASON_GUIDE.items():
        assert len(meaning) > 20 and len(fix) > 10, code
    allow = [c for c in Reason if c.decision == Decision.ALLOW]
    assert all(REASON_GUIDE[c][1] == "Nothing to fix." or "Nothing to fix" in REASON_GUIDE[c][1] for c in allow)
