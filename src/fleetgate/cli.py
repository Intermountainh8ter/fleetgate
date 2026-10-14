"""Command-line interface: simulate, bench, audit verify|replay, postmortem, export-metrics and catalogue browsing.

Every command that reports results has a `--json` mode that prints exactly one JSON document on stdout (prompts and
progress go to stderr), so the output can be piped to `jq`. Exit status: 0 success, 1 a check failed (audit chain,
safety invariant), 2 bad input (unknown scenario, malformed file, bad flag).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .adversary import check_invariants
from .approvals import AutoApprover, InteractiveApprover, LatencyApprover
from .audit import AuditLog, FileAnchor, replay
from .dashboard import render_summary, render_tick
from .fleet import FAULT_SPECS, GROUP_FAULTS, Fleet
from .llm import LLM
from .metrics import from_orchestrator, from_replay
from .orchestrator import approve_all, deny_all
from .policy import REASON_GUIDE, Policy, PolicyConfig, Reason, available_policies
from .postmortem import PostmortemAgent
from .runbooks import CATALOG, Tier
from .runner import RunResult, run_scenario
from .scenarios import Scenario, get_scenario, load_scenarios
from .schema import SchemaError

APPROVER_CHOICES = ("auto", "deny", "interactive", "hold", "humans")
NON_INTERACTIVE = ("auto", "deny", "hold", "humans")


class CliError(Exception):
    """A user-facing error: printed as `error: ...` with exit status 2."""


# ---- helpers ----------------------------------------------------------------------------------------------


def make_approver(kind: str, json_mode: bool = False) -> Any:
    if kind == "auto":
        return approve_all
    if kind == "deny":
        return deny_all
    if kind == "hold":
        return AutoApprover("hold")
    if kind == "humans":
        return LatencyApprover(2, 1)
    if kind == "interactive":
        if json_mode:  # keep stdout a single JSON document: prompts go to stderr
            def ask(prompt: str) -> str:
                print(prompt, end="", file=sys.stderr, flush=True)
                return input()

            return InteractiveApprover(input_fn=ask, output_fn=lambda s: print(s, file=sys.stderr))
        return InteractiveApprover()
    raise CliError(f"unknown approver {kind!r}")


def make_llm(name: str) -> LLM | None:
    if name == "none":
        return None
    try:
        from .llm import AnthropicLLM

        return AnthropicLLM()
    except ImportError as exc:
        raise CliError("--llm anthropic needs the optional SDK: pip install 'fleetgate[llm]'") from exc
    except Exception as exc:  # missing API key and similar
        raise CliError(f"could not start the Anthropic client: {exc}") from exc


def emit(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    cells = [[("-" if c is None else (f"{c:.2f}" if isinstance(c, float) else str(c))) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) if cells else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)), "  ".join("-" * w for w in widths)]
    lines += ["  ".join(c.ljust(w) for c, w in zip(r, widths)) for r in cells]
    return "\n".join(lines)


def load_scenario_arg(name: str, directory: str | None) -> Scenario:
    try:
        return get_scenario(name, directory)
    except KeyError as exc:
        raise CliError(exc.args[0]) from exc
    except (OSError, SchemaError, ValueError) as exc:
        raise CliError(f"cannot load scenario {name!r}: {exc}") from exc


def load_policy_arg(name: str | None) -> PolicyConfig | None:
    if not name:
        return None
    try:
        return PolicyConfig.load(name)
    except (OSError, SchemaError, ValueError) as exc:
        raise CliError(f"cannot load policy {name!r}: {exc}") from exc


def load_log(path: str, key_env: str | None = None) -> AuditLog:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"audit log not found: {path}")
    key = None
    if key_env:
        key = os.environ.get(key_env)
        if key is None:
            raise CliError(f"environment variable {key_env} is not set")
    try:
        return AuditLog.load(p, key=key)
    except (ValueError, KeyError) as exc:
        raise CliError(f"{path} is not a valid audit log: {exc}") from exc


# ---- simulate ---------------------------------------------------------------------------------------------


def cmd_simulate(a: argparse.Namespace) -> int:
    scenario = load_scenario_arg(a.scenario, a.scenario_dir)
    policy = load_policy_arg(a.policy)
    if a.anchor and not a.audit:
        raise CliError("--anchor needs --audit FILE")
    audit = AuditLog(a.audit, anchor=FileAnchor(a.anchor) if a.anchor else None) if a.audit else None
    if audit and audit.entries:
        raise CliError(f"{a.audit} already holds {len(audit.entries)} entries; refusing to append a second run")
    llm = make_llm(a.llm)
    show = not a.json and not a.quiet

    def on_tick(orch: Any) -> None:
        if show and orch.fleet.tick % a.every == 0:
            print(render_tick(orch))

    result = run_scenario(scenario, ticks=a.ticks, policy=policy, approver=make_approver(a.approver, a.json),
                          audit=audit, dry_run=a.dry_run, correlate=not a.no_correlate, llm=llm, on_tick=on_tick,
                          seed_offset=a.seed_offset)
    violations = check_invariants(result.orchestrator)
    if a.audit:
        result.orchestrator.audit.checkpoint()  # seal the run: a Merkle root over everything since the last checkpoint
    if a.json:
        emit(simulate_report(result, violations))
    else:
        print(render_summary(result.orchestrator))
        print(outcome_table(result))
        print("safety invariants: " + ("all held" if not violations else f"{len(violations)} VIOLATED"))
        for v in violations[:10]:
            print("  -", v)
        if a.audit:
            head = result.orchestrator.audit.head
            anchors = f" --anchors {a.anchor}" if a.anchor else ""
            print(f"audit log: {a.audit} (head {head[:16]}...); verify with: fleetgate audit verify {a.audit}{anchors}")
    return 1 if violations else 0


def simulate_report(result: RunResult, violations: list[str]) -> dict[str, Any]:
    o = result.orchestrator
    return {"summary": result.summary(), "outcomes": [x.to_dict() for x in result.outcomes],
            "incidents": [r.to_dict() for r in o.records.values()], "pages": o.pages,
            "executed": [{"tick": t, "runbook": rb, "host": h} for t, rb, h in o.executed],
            "audit_head": o.audit.head, "safety_violations": violations, "events": result.events}


def outcome_table(result: RunResult) -> str:
    if not result.outcomes:
        return "no faults were injected"
    rows = [[o.host, o.fault, o.injected_tick, o.detected_tick, o.ttd, o.status, o.ttr] for o in result.outcomes[:40]]
    more = f"\n... and {len(result.outcomes) - 40} more" if len(result.outcomes) > 40 else ""
    headers = ["host", "fault", "injected", "detected", "TTD", "status", "TTR"]
    return "ground-truth faults\n" + table(headers, rows) + more


# ---- bench ------------------------------------------------------------------------------------------------


def bench_cell(scenarios: dict[str, Scenario], names: list[str], pol: str | None, who: str,
               per: list[dict[str, Any]]) -> dict[str, Any]:
    agg = {"scenarios": 0, "faults": 0, "detected": 0, "resolved": 0, "contained": 0, "pages": 0, "violations": 0}
    ttr: list[float] = []
    label = pol or "scenario default"
    for n in names:
        r = run_scenario(scenarios[n], policy=PolicyConfig.load(pol) if pol else None, approver=make_approver(who))
        s = r.summary()
        v = len(check_invariants(r.orchestrator))
        agg["scenarios"] += 1
        for key, src in (("faults", "faults_injected"), ("detected", "faults_detected"),
                         ("resolved", "faults_resolved"), ("contained", "faults_contained"), ("pages", "pages")):
            agg[key] += s[src]
        agg["violations"] += v
        ttr += [o.ttr for o in r.outcomes if o.ttr is not None]
        per.append({"policy": label, "approver": who, "scenario": n, "faults": s["faults_injected"],
                    "detected": s["faults_detected"], "resolved": s["faults_resolved"],
                    "contained": s["faults_contained"], "pages": s["pages"], "violations": v})
    return {"policy": label, "approver": who, **agg, "mttr_mean": round(sum(ttr) / len(ttr), 2) if ttr else None}


def cmd_bench(a: argparse.Namespace) -> int:
    scenarios = require_scenarios(a.scenario_dir)
    names = sorted(scenarios)
    if a.quick:
        names = names[::3]
    policies = a.policy or [None]
    approvers = a.approver or ["auto", "deny"]
    per: list[dict[str, Any]] = []
    rows = [bench_cell(scenarios, names, pol, who, per) for pol in policies for who in approvers]
    bad = sum(r["violations"] for r in rows)
    if a.json:
        emit({"rows": rows, "per_scenario": per if a.per_scenario else None, "violations": bad})
        return 1 if bad else 0
    print(f"{len(names)} scenarios x {len(policies)} polic{'y' if len(policies) == 1 else 'ies'} x "
          f"{len(approvers)} approver(s). These are simulator results: see the README for what that means.")
    print(table(["policy", "approver", "faults", "detected", "resolved", "contained", "pages", "MTTR", "violations"],
                [[r["policy"], r["approver"], r["faults"], r["detected"], r["resolved"], r["contained"], r["pages"],
                  r["mttr_mean"], r["violations"]] for r in rows]))
    if a.per_scenario:
        print()
        print(table(["scenario", "policy", "approver", "faults", "detected", "resolved", "contained", "pages"],
                    [[p["scenario"], p["policy"], p["approver"], p["faults"], p["detected"], p["resolved"],
                      p["contained"], p["pages"]] for p in per]))
    print("full eval suite (detectors, Monte Carlo sweep, adversarial): python evals/run_evals.py")
    return 1 if bad else 0


# ---- audit ------------------------------------------------------------------------------------------------


def cmd_audit_verify(a: argparse.Namespace) -> int:
    log = load_log(a.file, a.key_env)
    anchors = FileAnchor(a.anchors).read() if a.anchors else None
    res = log.verify_full(require_signatures=a.require_signatures, anchors=anchors)
    if a.json:
        emit(res.to_dict())
    elif res.ok:
        sig = "signatures verified" if res.signed else "no key given: hash chain and Merkle checkpoints only"
        extra = ""
        if res.unchecked_signatures:
            extra = f"; {res.unchecked_signatures} signed entries NOT checked (pass --key-env)"
        anc = f"; {len(anchors)} external anchor(s) matched" if anchors else ""
        print(f"OK: {res.entries} entries, {res.checkpoints} Merkle checkpoint(s), {sig}{extra}{anc}")
    else:
        print(f"FAILED at entry {res.first_bad_seq}: {res.problems[0]}")
        for p in res.problems[1:5]:
            print("  also:", p)
    return 0 if res.ok else 1


def cmd_audit_replay(a: argparse.Namespace) -> int:
    log = load_log(a.file, a.key_env)
    res = log.verify_full()
    st = replay(log.entries)
    if a.json:
        emit({"verified": res.ok, **st.to_dict()})
        return 0 if res.ok else 1
    chain = "OK" if res.ok else "BROKEN (state below is untrusted)"
    print(f"replayed {len(log.entries)} entries up to tick {st.last_tick}; chain {chain}")
    print(f"drained hosts: {', '.join(sorted(st.drained)) or 'none'}; "
          f"open tickets: {', '.join(sorted(st.ticketed)) or 'none'}")
    print(table(["incident", "signal", "status", "severity", "opened", "closed", "executed", "denied"],
                [[i["id"][:42], i["signal"], i["status"], i["severity"], i["opened_tick"], i["closed_tick"],
                  len(i["executed"]), len(i["denied"])] for i in st.incidents.values()]))
    print(f"actions executed: {len(st.executed)} {dict(sorted(st.runbook_counts.items()))}")
    print(f"audited verdicts: {dict(sorted(st.decisions.items()))}")
    kinds = ", ".join(sorted({v["status"] for v in st.approvals.values()})) or "none"
    print(f"approvals: {len(st.approvals)} ({kinds}); pages: {len(st.pages)}; checkpoints: {st.checkpoints}")
    return 0 if res.ok else 1


# ---- postmortem -------------------------------------------------------------------------------------------


def cmd_postmortem(a: argparse.Namespace) -> int:
    log = load_log(a.file, a.key_env)
    agent = PostmortemAgent(make_llm(a.llm))
    ids = agent.incident_ids(log.entries)
    if not ids:
        raise CliError("the audit log contains no incidents")
    if a.incident:
        if a.incident not in ids:
            shown = ", ".join(ids[:10]) + ("..." if len(ids) > 10 else "")
            raise CliError(f"incident {a.incident!r} not in the log; known: {shown}")
        chosen = [a.incident]
    elif a.all:
        chosen = ids
    else:
        st = replay(log.entries)
        listing = [{"id": i, "signal": st.incidents[i]["signal"], "status": st.incidents[i]["status"]} for i in ids]
        if a.json:
            emit(listing)
        else:
            print("incidents in this log (pass --incident ID for a postmortem, or --all):")
            print(table(["incident", "signal", "status"], [[x["id"], x["signal"], x["status"]] for x in listing]))
        return 0
    pms = [agent.write(log.entries, i) for i in chosen]
    if a.json:
        emit([pm.to_dict() for pm in pms] if len(pms) > 1 else pms[0].to_dict())
    else:
        print("\n".join(pm.markdown() for pm in pms))
    return 0


# ---- export-metrics ---------------------------------------------------------------------------------------


def cmd_export_metrics(a: argparse.Namespace) -> int:
    if bool(a.audit) == bool(a.scenario):
        raise CliError("give exactly one of --audit FILE or --scenario NAME")
    if a.audit:
        text = from_replay(replay(load_log(a.audit, a.key_env).entries)).render()
    else:
        scenario = load_scenario_arg(a.scenario, a.scenario_dir)
        result = run_scenario(scenario, ticks=a.ticks, policy=load_policy_arg(a.policy),
                              approver=make_approver(a.approver))
        text = from_orchestrator(result.orchestrator).render()
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"wrote {len(text.splitlines())} lines to {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


# ---- catalogue browsing -----------------------------------------------------------------------------------


def require_scenarios(directory: str | None) -> dict[str, Scenario]:
    sc = load_scenarios(directory)
    if not sc:
        raise CliError("no scenario files found; run from the repository root, or pass --scenario-dir DIR / set "
                       "$FLEETGATE_SCENARIO_DIR (a pip-installed fleetgate does not bundle the scenarios)")
    return sc


def cmd_scenarios(a: argparse.Namespace) -> int:
    sc = require_scenarios(a.scenario_dir)
    if a.json:
        emit([s.to_dict() for s in sc.values()])
        return 0
    print(table(["scenario", "hosts", "ticks", "policy", "faults", "description"],
                [[n, s.fleet.get("hosts", 30), s.ticks, s.policy, len(s.faults) or "-", s.description[:70]]
                 for n, s in sc.items()]))
    return 0


def cmd_policies(a: argparse.Namespace) -> int:
    if a.name:
        cfg = load_policy_arg(a.name)
        assert cfg is not None
        if a.json:
            emit(cfg.to_dict())
        else:
            print("\n".join(Policy(Fleet(10), cfg).explain()))
        return 0
    names = available_policies()
    if a.json:
        emit([PolicyConfig.load(n).to_dict() for n in names])
    else:
        print(table(["policy", "description"], [[n, PolicyConfig.load(n).description[:100]] for n in names]))
    return 0


def cmd_runbooks(a: argparse.Namespace) -> int:
    if a.json:
        emit([r.to_dict() for r in CATALOG.values()])
        return 0
    order = {Tier.REVERSIBLE: 0, Tier.DISRUPTIVE: 1, Tier.DESTRUCTIVE: 2}
    rows = [[r.id, r.tier.name, r.scope, r.duration_ticks, r.rollback, ",".join(r.preconditions) or "-"]
            for r in sorted(CATALOG.values(), key=lambda r: (order[r.tier], r.id))]
    print(table(["runbook", "tier", "scope", "ticks", "rollback", "preconditions"], rows))
    return 0


def cmd_explain(a: argparse.Namespace) -> int:
    """Look up a policy reason code: what it means and how to fix it."""
    if not a.code:
        if a.json:
            emit([{"code": r.value, "decision": r.decision.value, "meaning": REASON_GUIDE[r][0],
                   "fix": REASON_GUIDE[r][1]} for r in Reason])
        else:
            print(table(["code", "decision", "meaning"],
                        [[r.value, r.decision.value, REASON_GUIDE[r][0][:90]] for r in Reason]))
            print("\nfleetgate explain CODE  for the fix")
        return 0
    wanted = a.code.strip().upper()
    hits = [r for r in Reason if wanted in (r.value, r.name)] or [r for r in Reason if wanted in r.value]
    if len(hits) != 1:
        raise CliError(f"no unique reason code matches {a.code!r}; known: {', '.join(r.value for r in Reason)}")
    r = hits[0]
    meaning, fix = REASON_GUIDE[r]
    if a.json:
        emit({"code": r.value, "decision": r.decision.value, "meaning": meaning, "fix": fix})
    else:
        print(f"{r.value}  ({r.decision.value})\n\nmeaning: {meaning}\nfix:     {fix}")
    return 0


def cmd_faults(a: argparse.Namespace) -> int:
    rows = [{"fault": s.name, "category": s.category, "severity": s.severity, "onset": s.mode,
             "cascades_to": [c[0] for c in s.cascades], "description": s.description} for s in FAULT_SPECS.values()]
    groups = [{"group_fault": g, "scope": sc, "per_host_fault": ph} for g, (sc, ph) in GROUP_FAULTS.items()]
    if a.json:
        emit({"faults": rows, "group_faults": groups})
        return 0
    print(table(["fault", "category", "severity", "onset", "cascades to"],
                [[r["fault"], r["category"], r["severity"], r["onset"], ",".join(r["cascades_to"]) or "-"]
                 for r in rows]))
    print("\ncorrelated (shared-infrastructure) faults:")
    print(table(["group fault", "scope", "per-host fault"],
                [[g["group_fault"], g["scope"], g["per_host_fault"]] for g in groups]))
    return 0


# ---- parser -----------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fleetgate", description="Policy-gated multi-agent incident response for a "
                                "simulated bare-metal fleet. Agents propose; a deterministic gate disposes.")
    p.add_argument("--version", action="version", version=f"fleetgate {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def scenario_dir(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--scenario-dir", default=None,
                        help="directory of scenario JSON files (default: ./scenarios, or $FLEETGATE_SCENARIO_DIR)")

    s = sub.add_parser("simulate", help="run a scenario: detect, triage, plan, gate, execute, verify")
    s.add_argument("--scenario", required=True, help="scenario name (see `fleetgate scenarios`) or a .json path")
    s.add_argument("--ticks", type=int, default=None, help="override the scenario's length")
    s.add_argument("--policy", default=None,
                   help="bundled policy name or a policy .json path (default: the scenario's own)")
    s.add_argument("--approver", choices=APPROVER_CHOICES, default="deny",
                   help="auto = approve every request, deny = reject every request, interactive = ask on stdin, "
                        "hold = never answer (tests escalation), humans = simulated on-call latency (default: deny)")
    s.add_argument("--dry-run", action="store_true", help="decide and audit everything but change nothing")
    s.add_argument("--quiet", action="store_true", help="skip the per-tick dashboard")
    s.add_argument("--every", type=int, default=1, help="print the dashboard every N ticks (default 1)")
    s.add_argument("--audit", default=None, help="write the hash-chained audit log to this file (sealed with a final "
                   "Merkle checkpoint; set $FLEETGATE_AUDIT_KEY to also HMAC-sign every entry)")
    s.add_argument("--anchor", default=None, help="also append each checkpoint's (seq, Merkle root) to this file: "
                   "keep it where the log writer cannot rewrite it, and pass it to `audit verify --anchors`")
    s.add_argument("--seed-offset", type=int, default=0, help="add to the scenario seed for a different random draw")
    s.add_argument("--no-correlate", action="store_true", help="disable rack/zone correlation (one incident per host)")
    s.add_argument("--llm", choices=("none", "anthropic"), default="none",
                   help="let a model write triage/root-cause sentences (never actions); needs fleetgate[llm]")
    s.add_argument("--json", action="store_true", help="print one JSON document on stdout")
    scenario_dir(s)
    s.set_defaults(fn=cmd_simulate)

    b = sub.add_parser("bench", help="replay the bundled scenarios; detection / resolution / MTTR per policy")
    b.add_argument("--policy", action="append", help="bundled policy (repeatable); default: each scenario's own")
    b.add_argument("--approver", action="append", choices=NON_INTERACTIVE, help="repeatable; default: auto and deny")
    b.add_argument("--quick", action="store_true", help="every third scenario")
    b.add_argument("--per-scenario", action="store_true", help="also print one row per scenario")
    b.add_argument("--json", action="store_true")
    scenario_dir(b)
    b.set_defaults(fn=cmd_bench)

    au = sub.add_parser("audit", help="verify or replay an audit log")
    asub = au.add_subparsers(dest="audit_command", required=True, metavar="ACTION")
    v = asub.add_parser("verify", help="check the hash chain, Merkle checkpoints, signatures and anchors")
    v.add_argument("file")
    v.add_argument("--key-env", default=None, metavar="VAR", help="environment variable holding the HMAC key")
    v.add_argument("--anchors", default=None, help="file of 'seq merkle_root' lines kept out of the writer's reach")
    v.add_argument("--require-signatures", action="store_true")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_audit_verify)
    r = asub.add_parser("replay", help="rebuild incidents, actions and drained hosts from the log alone")
    r.add_argument("file")
    r.add_argument("--key-env", default=None, metavar="VAR")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_audit_replay)

    pm = sub.add_parser("postmortem", help="write a postmortem from an audit log")
    pm.add_argument("file")
    pm.add_argument("--incident", default=None, help="incident id (omit to list the incidents)")
    pm.add_argument("--all", action="store_true", help="every incident in the log")
    pm.add_argument("--key-env", default=None, metavar="VAR")
    pm.add_argument("--llm", choices=("none", "anthropic"), default="none",
                    help="a model may write only the summary paragraph; the template is the fallback")
    pm.add_argument("--json", action="store_true")
    pm.set_defaults(fn=cmd_postmortem)

    m = sub.add_parser("export-metrics", help="Prometheus text format from an audit log or a fresh simulation")
    m.add_argument("--audit", default=None)
    m.add_argument("--key-env", default=None, metavar="VAR")
    m.add_argument("--scenario", default=None)
    m.add_argument("--ticks", type=int, default=None)
    m.add_argument("--policy", default=None)
    m.add_argument("--approver", choices=NON_INTERACTIVE, default="deny")
    m.add_argument("--out", default=None, help="write to a file instead of stdout")
    scenario_dir(m)
    m.set_defaults(fn=cmd_export_metrics)

    sc = sub.add_parser("scenarios", help="list the bundled scenarios")
    sc.add_argument("--json", action="store_true")
    scenario_dir(sc)
    sc.set_defaults(fn=cmd_scenarios)
    po = sub.add_parser("policies", help="list bundled policies, or explain one")
    po.add_argument("name", nargs="?")
    po.add_argument("--json", action="store_true")
    po.set_defaults(fn=cmd_policies)
    rb = sub.add_parser("runbooks", help="list the runbook catalogue with tiers")
    rb.add_argument("--json", action="store_true")
    rb.set_defaults(fn=cmd_runbooks)
    ex = sub.add_parser("explain", help="what a policy reason code means and how to fix it")
    ex.add_argument("code", nargs="?", help="e.g. DENY_COOLDOWN (omit to list every code)")
    ex.add_argument("--json", action="store_true")
    ex.set_defaults(fn=cmd_explain)
    fa = sub.add_parser("faults", help="list the simulated fault types")
    fa.add_argument("--json", action="store_true")
    fa.set_defaults(fn=cmd_faults)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # `fleetgate ... | head`
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
