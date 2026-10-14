"""Prometheus text export and the plain-stdout dashboard."""
import re

from fleetgate.audit import replay
from fleetgate.dashboard import render_summary, render_tick
from fleetgate.metrics import MetricsRegistry, _escape, from_orchestrator, from_replay
from fleetgate.orchestrator import approve_all
from fleetgate.runner import run_scenario
from fleetgate.scenarios import Scenario

SCN = Scenario.from_dict({
    "name": "disk", "fleet": {"hosts": 30, "seed": 5}, "ticks": 30,
    "events": [{"tick": 2, "type": "inject", "host": {"role": "worker", "nth": 0}, "fault": "disk_failing"}]})

PROM_LINE = re.compile(r'^(# (HELP|TYPE) [a-z_]+ .*|[a-z_]+(\{[a-z_]+="([^"\\]|\\.)*"(,[a-z_]+="([^"\\]|\\.)*")*\})? '
                       r'-?[0-9.e+]+)$')


def test_registry_renders_help_type_and_samples_once_per_metric():
    m = MetricsRegistry("x")
    m.add("temp", 1.5, {"host": "a"}, help_text="temperature")
    m.add("temp", 2, {"host": "b"})
    m.add("jobs_total", 7, kind="counter", help_text="jobs")
    out = m.render()
    assert out.count("# HELP x_temp temperature") == 1 and out.count("# TYPE x_temp gauge") == 1
    assert 'x_temp{host="a"} 1.5' in out and 'x_temp{host="b"} 2' in out
    assert "# TYPE x_jobs_total counter" in out and "x_jobs_total 7" in out and out.endswith("\n")


def test_label_values_are_escaped_per_the_text_format():
    assert _escape('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
    m = MetricsRegistry()
    m.add("g", 1, {"k": 'say "hi"\n'})
    assert 'fleetgate_g{k="say \\"hi\\"\\n"} 1' in m.render()


def test_orchestrator_export_is_valid_prometheus_text_with_the_expected_series():
    r = run_scenario(SCN, approver=approve_all)
    text = from_orchestrator(r.orchestrator).render()
    for line in text.strip().splitlines():
        assert PROM_LINE.match(line), line
    for needle in ('fleetgate_incidents{status="resolved"} 1', "fleetgate_actions_executed_total 4",
                   'fleetgate_runbook_executions_total{runbook="replace_disk"} 1',
                   'fleetgate_policy_decisions_total{code="APPROVAL_DESTRUCTIVE_TIER"}',
                   'fleetgate_approvals{status="approved"} 1', "fleetgate_audit_chain_ok 1",
                   "fleetgate_mttr_ticks_mean",
                   'fleetgate_role_hosts{role="worker",state="total"}', 'fleetgate_fleet_metric_avg{metric="temp_c"}',
                   "fleetgate_hosts_total 30", "# TYPE fleetgate_incidents_total counter"):
        assert needle in text, needle


def test_replay_export_matches_the_live_counters():
    r = run_scenario(SCN, approver=approve_all)
    live = from_orchestrator(r.orchestrator).render()
    replayed = from_replay(replay(r.orchestrator.audit.entries)).render()
    for needle in ('fleetgate_runbook_executions_total{runbook="replace_disk"} 1', "fleetgate_actions_executed_total 4",
                   'fleetgate_incidents{status="resolved"} 1', "fleetgate_hosts_drained 0", "fleetgate_pages_total 0"):
        assert needle in replayed, needle
    assert 'fleetgate_incidents{status="resolved"} 1' in live
    for line in replayed.strip().splitlines():
        assert PROM_LINE.match(line), line


def test_dashboard_tick_block_shows_incidents_faulty_hosts_and_actions():
    r = run_scenario(SCN, approver=approve_all, ticks=6)
    block = render_tick(r.orchestrator)
    assert block.startswith("=" * 110) and "tick     6" in block and "incident" in block
    assert "disk_failing" in block and "drain_host:" in block and "h001" in block
    assert all(len(line) <= 160 for line in block.splitlines())
    assert "\x1b[" not in block  # no colour codes
    quiet = run_scenario(Scenario.from_dict({"name": "q", "fleet": {"hosts": 12, "seed": 1}, "ticks": 3, "events": []}))
    qb = render_tick(quiet.orchestrator)
    assert "incidents open 0" in qb and "faulty hosts" not in qb


def test_dashboard_shows_pages_and_summary():
    from fleetgate.orchestrator import deny_all

    r = run_scenario(SCN, approver=deny_all)
    last_page_tick = max(p["tick"] for p in r.orchestrator.pages)
    # replay the final page tick through the renderer by faking the clock
    r.orchestrator.fleet.tick = last_page_tick
    assert "PAGE:" in render_tick(r.orchestrator)
    s = render_summary(r.orchestrator)
    for needle in ("run complete after", "(live)", "incidents: 1", "audit:", "chain OK", "policy decisions:"):
        assert needle in s
    dry = run_scenario(SCN, dry_run=True)
    assert "DRY RUN" in render_summary(dry.orchestrator)
