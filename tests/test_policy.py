from fleetgate.fleet import Fleet
from fleetgate.policy import Decision, Policy, PolicyConfig


def fleet_with_roles():
    f = Fleet(20, seed=1)
    for i, h in enumerate(f.hosts.values()):
        h.role = "db-primary" if i == 0 else "worker"
    return f, list(f.hosts)


def test_unknown_runbook_and_host_denied():
    f, ids = fleet_with_roles()
    p = Policy(f)
    assert p.evaluate("format_c", ids[1]).decision == Decision.DENY
    assert p.evaluate("restart_service", "nope").decision == Decision.DENY


def test_reversible_on_worker_allowed():
    f, ids = fleet_with_roles()
    assert Policy(f).evaluate("restart_service", ids[1]).decision == Decision.ALLOW


def test_destructive_needs_approval_even_on_worker():
    f, ids = fleet_with_roles()
    assert Policy(f).evaluate("replace_disk", ids[1]).decision == Decision.NEEDS_APPROVAL


def test_protected_role_needs_approval_for_reversible():
    f, ids = fleet_with_roles()
    assert Policy(f).evaluate("restart_service", ids[0]).decision == Decision.NEEDS_APPROVAL


def test_blast_radius_caps_drains():
    f, ids = fleet_with_roles()
    p = Policy(f, PolicyConfig(max_drained_fraction=0.10, max_actions_per_tick=99))
    results = []
    for h in ids[1:6]:
        v = p.evaluate("drain_host", h)
        results.append(v.decision)
        if v.decision == Decision.ALLOW:
            f.hosts[h].drained = True
    assert results.count(Decision.ALLOW) == 2  # 10% of 20 hosts
    assert Decision.DENY in results


def test_cooldown_blocks_repeat():
    f, ids = fleet_with_roles()
    p = Policy(f)
    p.record("restart_service", ids[1])
    assert p.evaluate("restart_service", ids[1]).decision == Decision.DENY
    f.tick += 5
    assert p.evaluate("restart_service", ids[1]).decision == Decision.ALLOW


def test_per_tick_budget():
    f, ids = fleet_with_roles()
    p = Policy(f, PolicyConfig(max_actions_per_tick=2))
    for h in ids[1:3]:
        p.record("restart_service", h)
    assert p.evaluate("restart_service", ids[4]).decision == Decision.DENY
