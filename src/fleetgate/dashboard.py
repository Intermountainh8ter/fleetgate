"""Plain-stdout dashboard: one block of fixed-width tables per tick. No curses, no colour codes."""
from __future__ import annotations

from .orchestrator import Orchestrator

KEY_METRICS = ("temp_c", "cpu_util", "mem_used_pct", "packet_loss_pct", "disk_latency_ms", "service_up")


def _row(cols: list[tuple[str, int]], values: list[object]) -> str:
    out = []
    for (_name, width), v in zip(cols, values):
        s = f"{v:.1f}" if isinstance(v, float) else str(v)
        out.append(s[:width].ljust(width) if not isinstance(v, (int, float)) else s[:width].rjust(width))
    return " ".join(out)


def _header(cols: list[tuple[str, int]]) -> str:
    return " ".join(n.ljust(w)[:w] for n, w in cols)


def render_tick(orch: Orchestrator, max_hosts: int = 12, width: int = 110) -> str:
    s = orch.snapshot()
    t = s["tick"]
    lines = ["=" * width,
             f"tick {t:>5}  load x{s['load']:.2f}  hosts {s['active']}/{s['hosts']} active  {s['drained']} drained  "
             f"{s['faulty']} faulty | incidents open {s['open']} resolved {s['resolved']} contained {s['contained']}"
             f" | pending approvals {s['pending_approvals']}  pages {s['pages']}"]
    opened = [r for r in orch.records.values() if r.status != "resolved" or r.active]  # open, contained, or working
    cols = [("incident", 38), ("sev", 8), ("root cause", 20), ("hosts", 6), ("steps", 36)]
    if opened:
        lines.append("-" * width)
        lines.append(_header(cols))
        for r in opened[:max_hosts]:
            steps = ",".join(f"{st.proposal.runbook}:{st.status[:4]}" for st in r.steps)[:36]
            lines.append(_row(cols, [r.incident.id, r.triage.severity if r.triage else "-",
                                     r.root_cause.hypothesis if r.root_cause else "-", len(r.hosts), steps]))
    faulty = list(orch.fleet.faulty_hosts())[:max_hosts]
    if faulty:
        lines.append("-" * width)
        hcols = [("host", 6), ("role", 11), ("rack", 14), ("state", 8), ("faults", 28)]
        hcols += [(m[:11], 11) for m in KEY_METRICS]
        lines.append(_header(hcols))
        for h in faulty:
            m = orch.fleet.last_sample.get(h.id, {})
            state = "drained" if h.drained else ("cordon" if h.cordoned else ("decom" if h.decommissioned else "up"))
            vals: list[object] = [h.id, h.role, h.rack, state, ",".join(h.faults)[:28]]
            vals += [m.get(k, "n/a") for k in KEY_METRICS]
            lines.append(_row(hcols, vals))
    acts = s["executed_this_tick"]
    if acts:
        lines.append("-" * width)
        lines.append("executed this tick: " + ", ".join(f"{rb}@{h}" for rb, h in acts))
    recent_pages = [p for p in orch.pages if p["tick"] == t]
    for p in recent_pages:
        lines.append(f"PAGE: {p['incident']}: {p['reason']}")
    return "\n".join(lines)


def render_summary(orch: Orchestrator) -> str:
    s = orch.summary()
    lines = ["-" * 60, f"run complete after {s['ticks']} ticks ({'DRY RUN' if s['dry_run'] else 'live'})",
             f"incidents: {s['incidents']} (resolved {s['resolved']}, contained {s['contained']}, open {s['open']})",
             f"actions executed: {s['executed']}; denied: {s['denied']}; pages: {s['pages']}; "
             f"verify failures: {s['verify_failures']}; rollbacks: {s['rollbacks']}",
             f"approvals: {s['approvals']}",
             f"mean MTTR: {s['mttr_mean']} ticks; drained fraction: {s['drained_fraction']:.1%}",
             f"audit: {s['audit_entries']} entries, chain {'OK' if s['audit_ok'] else 'BROKEN'}"]
    if s["decisions"]:
        lines.append("policy decisions: " + ", ".join(f"{k}={v}" for k, v in sorted(s["decisions"].items())))
    return "\n".join(lines)
