# fleetgate

Multi-agent incident response for a bare-metal fleet, built around one rule: **agents propose, a
policy gate disposes.** Triage and planning agents (LLM-backed or heuristic) can only name actions
from a closed runbook catalogue; every proposal passes a deterministic policy gate before anything
runs, and every step lands in a hash-chained audit log.

```
telemetry ─► detector (thresholds + 2-tick hysteresis) ─► incident
          ─► TriageAgent (severity; LLM may write the summary only)
          ─► Planner (heuristic playbook | LLM JSON plan)
          ─► Policy gate ─► ALLOW ─────────────► execute ─► AuditLog
                         ├► NEEDS_APPROVAL ─► human approver callback
                         └► DENY (unknown runbook/host, cooldown, blast radius, action budget)
```

## Policy gate

| Check | Result |
|---|---|
| Runbook id not in catalogue, or host unknown | DENY |
| Same runbook on same host within cooldown (5 ticks) | DENY (anti-flapping) |
| More than 3 actions in a tick | DENY |
| `drain_host` that would push drained hosts above 10% of the fleet | DENY (blast radius) |
| Destructive runbook (`replace_disk`, `reboot_host`) | NEEDS_APPROVAL |
| Any action on a protected role (`db-primary`, `validator`) | NEEDS_APPROVAL |
| Reversible action on an unprotected host | ALLOW |

A malformed or empty LLM plan results in no actions (escalate to a human), never a guess.

## Results

```
python evals/run_evals.py
```

120 seeded single-fault scenarios, 30 hosts, 25-tick horizon:

| | detected | resolved | contained only | closed |
|---|---|---|---|---|
| approver = approve_all | 120/120 | 72 | 48 | 1.000 |
| approver = deny_all | 120/120 | 49 | 36 | 0.708 |

("contained" = host drained so traffic is safe but the fault remains for DC-ops to fix.)

- False positives: 0 incidents across 20 healthy fleets x 100 ticks x 30 hosts.
- **Gate under attack:** a test-double planner emits hallucinated runbooks, a fleet-wide reboot,
  fleet-wide drain, preventive disk replacement, and a nonexistent host, in shuffled order, across
  40 seeded fleets with 3 simultaneous faults. Result with both `deny_all` and `approve_all`
  approvers: 0 unknown runbooks executed, 0 destructive or protected-host actions without an
  approval record, worst drained fraction 10.0% (the cap), audit chain intact.
  `approve_all` still cannot exceed the blast-radius cap, because approval does not bypass DENY.

## What these numbers do and do not mean

- **The simulator is idealised.** Faults are step changes, noise is Gaussian, thresholds are
  well separated, and a fix instantly clears a fault. 120/120 detection and 0 false positives show
  that the plumbing and safety logic work, not that the detector would do so on real BMC/SMART
  data. Real telemetry needs per-fleet threshold calibration and a measured false-positive rate.
- The 0.708 `deny_all` figure is the cost of the safety policy (destructive and protected-host
  actions waiting for a human), not a detection failure.
- The audit log is tamper-**evident** (hash chain), not tamper-proof: someone who can rewrite the
  whole file can recompute the chain. Anchor the head hash externally for real use.
- No real hardware, BMC/IPMI, scheduler, or ticketing integration; runbooks mutate the simulator.
- The Anthropic-backed paths (`LLMPlanner`, LLM triage summaries) are exercised only with a
  scripted stand-in in tests.

## Usage

```python
from fleetgate import Fleet, Orchestrator
from fleetgate.orchestrator import approve_all

fleet = Fleet(30, seed=1)
fleet.inject("h003", "service_down")
orch = Orchestrator(fleet, approver=approve_all)
for _ in range(5):
    orch.tick()
print(orch.executed, orch.audit.verify())
```
```
pip install -e ".[dev,llm]" && pytest -q && python evals/run_evals.py
```
`FLEETGATE_MODEL` overrides the model id.
