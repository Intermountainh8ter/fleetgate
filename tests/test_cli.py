"""The `fleetgate` command line: every subcommand, JSON mode, exit codes, and a real subprocess smoke test."""
import json
import subprocess
import sys
import types

import pytest

from fleetgate import __version__
from fleetgate.cli import CliError, main, make_approver, make_llm
from fleetgate.policy import Reason

SCN = "disk_failing_worker"


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def jrun(capsys, *argv):
    code, out, err = run(capsys, *argv)
    return code, json.loads(out), err


# ---- plumbing -------------------------------------------------------------------------------------------


def test_version_and_help_and_missing_command(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and f"fleetgate {__version__}" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    out = capsys.readouterr().out
    assert e.value.code == 0 and all(c in out for c in ("simulate", "bench", "audit", "postmortem", "export-metrics"))
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2


def test_python_dash_m_entry_point_works():
    r = subprocess.run([sys.executable, "-m", "fleetgate", "--version"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == f"fleetgate {__version__}"
    r = subprocess.run([sys.executable, "-m", "fleetgate", "simulate", "--scenario", "service_crash_worker",
                        "--quiet", "--approver", "auto"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "safety invariants: all held" in r.stdout


def test_user_errors_exit_2_with_a_message_on_stderr(capsys):
    code, out, err = run(capsys, "simulate", "--scenario", "no_such_scenario")
    assert code == 2 and out == "" and err.startswith("error: unknown scenario 'no_such_scenario'; known: ")
    code, _, err = run(capsys, "simulate", "--scenario", SCN, "--policy", "nope")
    assert code == 2 and "cannot load policy 'nope'" in err
    code, _, err = run(capsys, "audit", "verify", "/no/such/file")
    assert code == 2 and "audit log not found" in err
    code, _, err = run(capsys, "simulate", "--scenario", SCN, "--anchor", "x.txt")
    assert code == 2 and "--anchor needs --audit" in err


def test_broken_pipe_and_interrupt_are_handled(monkeypatch, capsys):
    import fleetgate.cli as cli

    monkeypatch.setattr(cli, "cmd_runbooks", lambda a: (_ for _ in ()).throw(BrokenPipeError()))
    assert main(["runbooks"]) == 0
    monkeypatch.setattr(cli, "cmd_runbooks", lambda a: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert main(["runbooks"]) == 130
    assert "interrupted" in capsys.readouterr().err
    assert main(["scenarios", "--scenario-dir", "/definitely/not/here"]) in (0, 2)


# ---- catalogue browsing ---------------------------------------------------------------------------------


def test_scenarios_listing_text_and_json(capsys):
    code, out, _ = run(capsys, "scenarios")
    assert code == 0 and "disk_failing_worker" in out and "tor_switch_rack_failure" in out
    code, data, _ = jrun(capsys, "scenarios", "--json")
    assert len(data) >= 30 and {"name", "events", "fleet", "expect"} <= set(data[0])


def test_scenario_dir_flag(capsys, tmp_path):
    (tmp_path / "one.json").write_text(json.dumps({"name": "one", "fleet": {"hosts": 10, "seed": 1}, "ticks": 5,
                                                   "events": []}))
    code, data, _ = jrun(capsys, "scenarios", "--json", "--scenario-dir", str(tmp_path))
    assert code == 0 and [d["name"] for d in data] == ["one"]
    code, out, _ = run(capsys, "simulate", "--scenario", "one", "--scenario-dir", str(tmp_path), "--quiet")
    assert code == 0 and "run complete after 5 ticks" in out and "no faults were injected" in out
    (tmp_path / "bad.json").write_text("{}")
    code, _, err = run(capsys, "simulate", "--scenario", str(tmp_path / "bad.json"))
    assert code == 2 and "cannot load scenario" in err


def test_policies_runbooks_faults_and_explain(capsys):
    code, out, _ = run(capsys, "policies")
    assert code == 0 and all(p in out for p in ("default", "strict", "permissive", "freeze", "canary"))
    code, out, _ = run(capsys, "policies", "strict")
    assert "approvals DESTRUCTIVE: 2 of" in out and "deny-list" in out
    code, data, _ = jrun(capsys, "policies", "strict", "--json")
    assert data["name"] == "strict" and data["max_drained_fraction"] == 0.05
    code, data, _ = jrun(capsys, "policies", "--json")
    assert len(data) == 5
    code, out, _ = run(capsys, "runbooks")
    assert "replace_disk" in out and out.index("REVERSIBLE") < out.index("DISRUPTIVE") < out.index("DESTRUCTIVE")
    code, data, _ = jrun(capsys, "runbooks", "--json")
    assert len(data) >= 25 and {"id", "tier", "preconditions", "verify", "rollback"} <= set(data[0])
    code, out, _ = run(capsys, "faults")
    assert "kernel_soft_lockup" in out and "tor_switch_failure" in out
    code, data, _ = jrun(capsys, "faults", "--json")
    assert len(data["faults"]) >= 20 and len(data["group_faults"]) == 3


def test_explain_exact_partial_listing_and_errors(capsys):
    code, out, _ = run(capsys, "explain", "DENY_COOLDOWN")
    assert code == 0 and "meaning:" in out and "fix:" in out
    assert run(capsys, "explain", "cooldown")[1].startswith("DENY_COOLDOWN")
    code, out, _ = run(capsys, "explain")
    assert all(r.value in out for r in Reason)
    code, data, _ = jrun(capsys, "explain", "--json")
    assert len(data) == len(Reason) and all(d["meaning"] and d["fix"] for d in data)
    code, data, _ = jrun(capsys, "explain", "DENY_BLAST_RADIUS", "--json")
    assert data["decision"] == "DENY"
    code, _, err = run(capsys, "explain", "NOPE_NOPE")
    assert code == 2 and "no unique reason code" in err
    code, _, err = run(capsys, "explain", "DENY")  # ambiguous prefix
    assert code == 2


# ---- simulate -------------------------------------------------------------------------------------------


def test_simulate_prints_the_dashboard_summary_and_outcomes(capsys):
    code, out, _ = run(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--ticks", "8")
    assert code == 0 and out.count("=" * 110) == 8 and "tick     8" in out
    assert "run complete after 8 ticks (live)" in out and "ground-truth faults" in out
    assert "safety invariants: all held" in out and "disk_failing" in out


def test_simulate_every_and_quiet(capsys):
    code, out, _ = run(capsys, "simulate", "--scenario", SCN, "--ticks", "10", "--every", "5")
    assert out.count("=" * 110) == 2
    code, out, _ = run(capsys, "simulate", "--scenario", SCN, "--ticks", "10", "--quiet")
    assert "=" * 110 not in out and "run complete" in out


def test_simulate_json_is_one_clean_document(capsys):
    code, doc, err = jrun(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--json")
    assert code == 0 and err == ""
    assert {"summary", "outcomes", "incidents", "pages", "executed", "audit_head", "safety_violations"} <= set(doc)
    assert doc["summary"]["faults_resolved"] == 1 and doc["safety_violations"] == []
    assert [e["runbook"] for e in doc["executed"]] == ["drain_host", "open_ticket", "replace_disk", "undrain_host"]
    assert doc["outcomes"][0]["fault"] == "disk_failing" and len(doc["audit_head"]) == 64


@pytest.mark.parametrize("kind,resolved", [("auto", 1), ("deny", 0), ("hold", 0), ("humans", 1)])
def test_approver_modes(capsys, kind, resolved):
    code, doc, _ = jrun(capsys, "simulate", "--scenario", SCN, "--approver", kind, "--json")
    assert doc["summary"]["faults_resolved"] == resolved and code == 0
    if kind == "hold":
        assert doc["summary"]["approvals"]["expired"] == 1 and doc["pages"]


def test_interactive_approver_prompts_on_stdin_and_json_stays_clean(capsys, monkeypatch):
    answers = iter(["y", "y", "y", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    code, doc, err = jrun(capsys, "simulate", "--scenario", SCN, "--approver", "interactive", "--json")
    assert doc["summary"]["faults_resolved"] == 1
    assert "approval needed: replace_disk" in err and "approve as" in err  # prompts went to stderr
    answers = iter(["y", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    code, out, err = run(capsys, "simulate", "--scenario", SCN, "--approver", "interactive", "--quiet")
    assert "approval needed: replace_disk" in out  # text mode: prompts share stdout


def test_dry_run_and_policy_override_and_seed_offset(capsys, tmp_path):
    code, doc, _ = jrun(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--dry-run", "--json")
    assert doc["summary"]["dry_run"] is True and doc["summary"]["faults_resolved"] == 0 and doc["executed"]
    code, doc, _ = jrun(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--policy", "strict", "--json")
    assert doc["summary"]["policy"] == "strict"
    custom = tmp_path / "mine.json"
    custom.write_text(json.dumps({"name": "mine", "max_actions_per_tick": 1}))
    code, doc, _ = jrun(capsys, "simulate", "--scenario", SCN, "--policy", str(custom), "--json")
    assert doc["summary"]["policy"] == "mine"
    a = jrun(capsys, "simulate", "--scenario", SCN, "--json", "--seed-offset", "0")[1]["audit_head"]
    b = jrun(capsys, "simulate", "--scenario", SCN, "--json", "--seed-offset", "3")[1]["audit_head"]
    assert a != b


def test_no_correlate_flag(capsys):
    code, doc, _ = jrun(capsys, "simulate", "--scenario", "tor_switch_rack_failure", "--approver", "auto",
                        "--no-correlate", "--json")
    assert len(doc["incidents"]) >= 10 and not any(i["id"].startswith("grp-") for i in doc["incidents"])


def test_simulate_exits_1_when_a_safety_invariant_is_violated(capsys, monkeypatch):
    import fleetgate.cli as cli

    monkeypatch.setattr(cli, "check_invariants", lambda orch: ["executed without a prior approval it needed: x"])
    code, out, _ = run(capsys, "simulate", "--scenario", SCN, "--quiet")
    assert code == 1 and "1 VIOLATED" in out and "- executed without a prior approval" in out


# ---- audit log lifecycle ------------------------------------------------------------------------------------


@pytest.fixture
def logged(tmp_path, capsys):
    path = tmp_path / "run.audit.jsonl"
    anchor = tmp_path / "run.anchors"
    code, out, _ = run(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--quiet", "--audit", str(path),
                       "--anchor", str(anchor))
    assert code == 0 and "audit log:" in out and "--anchors" in out
    return path, anchor


def test_audit_verify_replay_and_sealing(logged, capsys):
    path, anchor = logged
    code, out, _ = run(capsys, "audit", "verify", str(path))
    assert code == 0 and out.startswith("OK: ") and "1 Merkle checkpoint(s)" in out  # sealed by the CLI
    code, out, _ = run(capsys, "audit", "verify", str(path), "--anchors", str(anchor))
    assert code == 0 and "external anchor(s) matched" in out
    code, doc, _ = jrun(capsys, "audit", "verify", str(path), "--json")
    assert doc["ok"] is True and doc["checkpoints"] == 1 and doc["problems"] == []
    code, out, _ = run(capsys, "audit", "replay", str(path))
    assert code == 0 and "chain OK" in out and "disk_failing" in out and "replace_disk" in out
    code, doc, _ = jrun(capsys, "audit", "replay", str(path), "--json")
    assert doc["verified"] and doc["runbook_counts"]["replace_disk"] == 1 and doc["drained"] == []


def test_audit_verify_detects_tampering_and_truncation(logged, capsys, tmp_path):
    path, anchor = logged
    lines = path.read_text().splitlines()
    rec = json.loads(lines[6])
    rec["host"] = "h999"
    bad = tmp_path / "tampered.jsonl"
    bad.write_text("\n".join(lines[:6] + [json.dumps(rec, sort_keys=True)] + lines[7:]) + "\n")
    code, out, _ = run(capsys, "audit", "verify", str(bad))
    assert code == 1 and "FAILED at entry 6" in out and "content altered" in out
    code, doc, _ = jrun(capsys, "audit", "verify", str(bad), "--json")
    assert code == 1 and doc["ok"] is False and doc["first_bad_seq"] == 6
    cut = tmp_path / "cut.jsonl"
    cut.write_text("\n".join(lines[:10]) + "\n")
    assert run(capsys, "audit", "verify", str(cut))[0] == 0  # a clean prefix passes on its own...
    code, out, _ = run(capsys, "audit", "verify", str(cut), "--anchors", str(anchor))
    assert code == 1 and "truncated" in out  # ...but not against the external anchor
    code, out, _ = run(capsys, "audit", "replay", str(bad))
    assert code == 1 and "BROKEN" in out


def test_signed_log_needs_its_key(tmp_path, capsys, monkeypatch):
    path = tmp_path / "signed.jsonl"
    monkeypatch.setenv("FLEETGATE_AUDIT_KEY", "k3y")
    assert run(capsys, "simulate", "--scenario", "service_crash_worker", "--quiet", "--audit", str(path))[0] == 0
    monkeypatch.delenv("FLEETGATE_AUDIT_KEY")
    code, out, _ = run(capsys, "audit", "verify", str(path))
    assert code == 0 and "signed entries NOT checked (pass --key-env)" in out
    monkeypatch.setenv("MY_KEY", "k3y")
    code, out, _ = run(capsys, "audit", "verify", str(path), "--key-env", "MY_KEY")
    assert code == 0 and "signatures verified" in out
    monkeypatch.setenv("MY_KEY", "wrong")
    code, out, _ = run(capsys, "audit", "verify", str(path), "--key-env", "MY_KEY")
    assert code == 1 and "bad signature" in out
    code, _, err = run(capsys, "audit", "verify", str(path), "--key-env", "UNSET_VAR_XYZ")
    assert code == 2 and "UNSET_VAR_XYZ is not set" in err
    code, out, _ = run(capsys, "audit", "verify", str(path), "--require-signatures")
    assert code == 1 and "signatures required" in out


def test_simulate_refuses_to_append_to_an_existing_log(logged, capsys):
    path, _ = logged
    code, _, err = run(capsys, "simulate", "--scenario", SCN, "--quiet", "--audit", str(path))
    assert code == 2 and "refusing to append a second run" in err


def test_malformed_log_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "junk.jsonl"
    bad.write_text("not json at all\n")
    code, _, err = run(capsys, "audit", "verify", str(bad))
    assert code == 2 and "is not a valid audit log" in err


# ---- postmortem, metrics, bench ---------------------------------------------------------------------------


def test_postmortem_listing_single_all_and_json(logged, capsys):
    path, _ = logged
    code, out, _ = run(capsys, "postmortem", str(path))
    assert code == 0 and "incidents in this log" in out and "inc-h" in out
    iid = out.split("inc-")[1].split()[0]
    iid = "inc-" + iid
    code, out, _ = run(capsys, "postmortem", str(path), "--incident", iid)
    assert code == 0 and out.startswith("# Postmortem: disk_failing on") and "## Timeline" in out
    code, doc, _ = jrun(capsys, "postmortem", str(path), "--incident", iid, "--json")
    assert doc["status"] == "resolved" and doc["root_cause"] == "disk_failing"
    code, docs, _ = jrun(capsys, "postmortem", str(path), "--all", "--json")
    assert docs["incident_id"] == iid  # a single incident prints as one document, several as a list
    code, listing, _ = jrun(capsys, "postmortem", str(path), "--json")
    assert listing[0]["status"] == "resolved"
    code, _, err = run(capsys, "postmortem", str(path), "--incident", "inc-nope")
    assert code == 2 and "not in the log" in err


def test_postmortem_on_a_log_without_incidents(tmp_path, capsys):
    path = tmp_path / "quiet.jsonl"
    quiet = ["simulate", "--scenario", "healthy_baseline", "--quiet", "--ticks", "5", "--audit", str(path)]
    assert run(capsys, *quiet)[0] == 0
    code, _, err = run(capsys, "postmortem", str(path))
    assert code == 2 and "contains no incidents" in err


def test_export_metrics_from_log_and_from_scenario(logged, capsys, tmp_path):
    path, _ = logged
    code, out, _ = run(capsys, "export-metrics", "--audit", str(path))
    assert code == 0 and 'fleetgate_runbook_executions_total{runbook="replace_disk"} 1' in out
    assert "# TYPE fleetgate_incidents_total counter" in out
    code, out, _ = run(capsys, "export-metrics", "--scenario", SCN, "--approver", "auto", "--ticks", "30")
    assert 'fleetgate_incidents{status="resolved"} 1' in out and "fleetgate_audit_chain_ok 1" in out
    dest = tmp_path / "metrics.prom"
    code, out, err = run(capsys, "export-metrics", "--scenario", SCN, "--out", str(dest))
    assert code == 0 and out == "" and "wrote" in err and dest.read_text().startswith("# HELP")
    assert run(capsys, "export-metrics")[0] == 2
    assert run(capsys, "export-metrics", "--audit", str(path), "--scenario", SCN)[0] == 2


def test_bench_text_and_json(capsys):
    code, out, _ = run(capsys, "bench", "--quick", "--policy", "default", "--approver", "auto")
    assert code == 0 and "scenarios x 1 policy x 1 approver(s)" in out and "default" in out and "violations" in out
    code, doc, _ = jrun(capsys, "bench", "--quick", "--policy", "default", "--policy", "strict", "--approver", "auto",
                        "--approver", "deny", "--json", "--per-scenario")
    assert code == 0 and len(doc["rows"]) == 4 and doc["violations"] == 0 and len(doc["per_scenario"]) == 56
    assert {r["approver"] for r in doc["rows"]} == {"auto", "deny"}
    by = {(r["policy"], r["approver"]): r for r in doc["rows"]}
    assert by[("default", "auto")]["resolved"] >= by[("default", "deny")]["resolved"]
    code, out, _ = run(capsys, "bench", "--quick", "--per-scenario", "--approver", "deny")
    assert "scenario default" in out and "evals/run_evals.py" in out


# ---- helpers ----------------------------------------------------------------------------------------------


def test_make_approver_and_make_llm(monkeypatch):
    for kind in ("auto", "deny", "hold", "humans", "interactive"):
        assert make_approver(kind) is not None
    assert make_approver("interactive", json_mode=True) is not None
    with pytest.raises(CliError):
        make_approver("telepathy")
    assert make_llm("none") is None
    monkeypatch.setitem(sys.modules, "anthropic", None)  # import fails -> a helpful message, not a traceback
    with pytest.raises(CliError, match=r"fleetgate\[llm\]"):
        make_llm("anthropic")
    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=None)
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    assert make_llm("anthropic") is not None

    def boom():
        raise RuntimeError("no api key")

    fake.Anthropic = boom
    with pytest.raises(CliError, match="no api key"):
        make_llm("anthropic")


def test_simulate_with_a_scripted_llm_writes_summaries_only(capsys, monkeypatch):
    import fleetgate.cli as cli
    from fleetgate.llm import ScriptedLLM

    monkeypatch.setattr(cli, "make_llm", lambda name: ScriptedLLM(["A one-line summary."]) if name != "none" else None)
    code, doc, _ = jrun(capsys, "simulate", "--scenario", SCN, "--approver", "auto", "--llm", "anthropic", "--json")
    assert code == 0 and doc["summary"]["faults_resolved"] == 1
