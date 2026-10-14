# Architecture

fleetgate has one design rule: **agents propose, a deterministic gate disposes.** Everything else follows from it.

## The trust boundary

```
 untrusted                         trusted, deterministic                         the world
 ---------                         ----------------------                         ---------
 LLM output, planner doubles  -->  sanitise -> schema -> catalogue/host match
 approver answers             -->  Policy.evaluate (pure, fails closed)  -->  Runbook.apply  -->  Fleet
                                   ApprovalQueue (N-of-M pools)                  (data-driven effects)
```

- A planner returns `Proposal(runbook, host, rationale)` objects. `sanitise_proposals` (orchestrator) drops anything
  that is not a `Proposal` with string fields, clamps id lengths and bounds how much of a plan is read, so hostile
  planner output cannot bloat the audit log or crash the loop.
- `LLMPlanner` additionally validates the model's text against `PLAN_SCHEMA` (a JSON array, at most 8 items, keys
  `runbook`/`host`/`rationale`, nothing else), retries once with the validation errors, then escalates with an empty
  plan. Hosts outside the incident and runbooks outside the catalogue are dropped before the gate ever sees them.
- `Policy.evaluate(runbook_id, host_id)` is a pure function of the proposal, the fleet state and the policy's own
  history. Any exception becomes `DENY_INTERNAL_ERROR`.
- `Runbook.apply` interprets declarative effects (`clear_fault`, `clear_faults`, `set_state`, `clear_all_faults`);
  nothing an agent emits is code.
- The audit log is append-only and hash-chained; the orchestrator is the only writer.

## Module map

| module | job |
|---|---|
| `fleet.py`, `topology.py` | the simulator: hosts, ~30 metrics, load curve, faults as data (`FAULT_SPECS`), cascades, rack-level faults, DC > room > rack > host topology |
| `detect.py` | threshold / EWMA / seasonal detectors over one hysteresis engine (`BaseDetector`) |
| `correlate.py` | folds simultaneous host incidents under shared infrastructure into one group incident |
| `agents.py` | `TriageAgent`, `RootCauseAgent`, planners (heuristic, LLM), hostile test doubles |
| `runbooks.py`, `data/runbooks.json` | closed catalogue as validated data: tiers, preconditions, probes, rollbacks, playbooks |
| `policy.py`, `data/policies/*.json` | the gate: rule chain, reason codes, approval requirements, canary-first |
| `approvals.py` | approval queue, N-of-M pools, escalation timers, approver implementations |
| `orchestrator.py` | the loop: detect, correlate, triage, plan, pre-flight, gate, approve, execute, verify, roll back |
| `verifier.py` | re-reads metrics after a runbook and proposes the rollback partner on failure |
| `audit.py` | hash chain, Merkle checkpoints, HMAC signatures, anchors, replay |
| `postmortem.py`, `capacity.py`, `metrics.py`, `dashboard.py` | derived views: postmortem from the log, spare-capacity arithmetic, Prometheus text, plain-stdout dashboard |
| `scenarios.py`, `runner.py` | scenario DSL (JSON, schema-validated) and a runner that scores a run against ground truth |
| `adversary.py` | hostile-input generators and `check_invariants`, the single definition of "the gate held" |
| `deteval.py` | detector precision/recall/F1/time-to-detect harness |
| `schema.py` | a small JSON-schema subset validator (zero runtime dependencies) |
| `cli.py` | the `fleetgate` command |

## One tick

`Orchestrator.tick()`:

1. `fleet.step()` produces metrics for every active (non-drained) host.
2. The detector emits host incidents (a signal must persist `confirm_ticks`; drained hosts close their incidents).
3. The correlator groups host incidents by (shared-infrastructure scope, hypothesis). A group needs
   `min_hosts` hosts and `min_fraction` of the scope; stragglers are absorbed for as long as the group is unresolved.
4. For each new incident: triage (deterministic severity and blast radius), root cause (cascade graph, topology),
   plan (heuristic playbook or LLM), sanitise, truncate to `max_plan_steps`.
5. **Pre-flight**: every step is gated once so the audit log shows a verdict for every proposal, including the
   hundreds a jailbroken planner might emit. Garbage (unknown runbook or host) is pruned; verdicts on real runbooks
   are marked `provisional` because earlier steps may satisfy their preconditions.
6. Steps run one per verification cycle. Each is re-evaluated by the gate when its turn comes. `NEEDS_APPROVAL`
   steps wait in the approval queue (page after `page_after_ticks`, expire after `expire_after_ticks`); transient
   denials (cooldown, tick budget, rate limit, quota, canary pending) wait up to 20 ticks; any other denial stops the
   plan and pages a human, because later steps assume earlier ones happened.
7. After `duration_ticks + 1` the verifier re-reads the host; a failed probe stops the plan, pages, and sends the
   rollback partner through the same gate and approval path.
8. Statuses update: `resolved` when the fault is gone, `contained` when every faulty host is drained.

## Invariants (checked, not just claimed)

`fleetgate.adversary.check_invariants` audits a finished run and is used by the tests, the evals and the CI gate:

1. no runbook outside the catalogue and none on the deny-list ever executes;
2. every execution is either REVERSIBLE on unprotected hosts under an ALLOW verdict, or DISRUPTIVE inside a
   maintenance window, or backed by an approved approval request filed *before* it ran;
3. the drained fraction never exceeds the policy cap;
4. the per-tick action budget holds;
5. a change freeze is never violated;
6. state preconditions held when each runbook ran (replayed from the log);
7. the audit hash chain verifies.

The seeded policy fuzzer (typosquats, Unicode lookalikes, spoofed hosts, oversized plans, nested JSON, feasible
destructive chains) runs against every bundled policy and approver. It was mutation-checked: nine deliberately broken
gates (destructive without approval, blast radius off, deny-list ignored, typosquat stripped, protected role ignored,
tick budget ignored, orchestrator skipping approval, preconditions skipped, maintenance window allowing destructive
work) are each caught.

## Decisions worth knowing

- **Pooled approvals.** An earlier design merged the tier's approvers and the protected-role approvers into one set,
  which let a plain `sre` approve work on a protected host. Requirements are now independent pools filled by
  distinct people (bipartite matching), and a policy whose pools could never be filled is rejected at load.
- **A denied real step stops the plan.** Pruning it and carrying on once let `undrain_host` run on a faulty host and
  flap forever. Only garbage proposals are dropped; a policy denial of a real runbook stops the plan and pages.
- **Rack-scope runbooks are judged by everything they touch.** Protected roles and the drain cap are checked over
  every target host, not just the proposed one.
- **Rollbacks are first-class.** They are exempt from plan abort and go through the gate and approval queue.
- **Audit entries are snapshots.** Fields are normalised to plain JSON when appended; an entry must never change
  after it was hashed (a growing group incident's host list once broke the chain).
- **With a key, every entry must be signed.** Stripped signatures fail verification rather than downgrading it.
- **Idealised on purpose.** The simulator is deterministic and seeded so that every number in the docs can be
  reproduced and every regression is a behaviour change, not noise.

## Extending

- **A fault**: add a `FaultSpec` to `fleet.FAULT_SPECS` (metrics, onset, cascades), a detector rule in
  `detect.RULES`, and a playbook in `runbooks.json`. The registry refuses to load a playbook for an unknown fault.
- **A runbook**: add an entry to `src/fleetgate/data/runbooks.json`; it is schema-validated at import
  (see [RUNBOOKS.md](RUNBOOKS.md)). Pick the lowest honest tier; a rollback may not be riskier than its action.
- **A policy**: copy a bundled JSON policy and pass `--policy path.json` ([POLICY.md](POLICY.md)).
- **A scenario**: drop a JSON file in `scenarios/`, then `python scripts/calibrate_expectations.py --write NAME`
  to record its bounds (review the numbers first) and `python scripts/gen_docs.py`.
- **An approver**: any object with `review(request, tick) -> list[Approval]`.
- **A planner**: any object with `plan(incident, triage) -> list[Proposal]`. It will be fuzzed by the same suite.
- **A detector**: subclass `BaseDetector` and implement `signals(host, metrics, tick)`.
