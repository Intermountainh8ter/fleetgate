# Changelog

All notable changes. Numbers here are from the commits and the recorded evals, not estimates.

## 0.2.0

The expansion release. The 0.1.0 baseline was 6 fault types, 7 runbooks, a 30-host simulator, 19 tests and a
120-scenario eval script.

### Added

- **Simulator**: 28 per-host fault types with step, ramp and intermittent onsets and cascades; 3 correlated
  rack-level faults (ToR switch, PDU, cooling zone); diurnal and weekly load; heteroscedastic noise; BMC/SSH outages
  that hide metrics; DC > room > rack > host topology.
- **Runbooks as data**: 32 runbooks in REVERSIBLE / DISRUPTIVE / DESTRUCTIVE tiers with preconditions, verification
  probes, rollback pairs, host and rack scope, durations and a dry-run mode; schema-validated at import.
- **Policy gate as JSON**: five bundled policies; reason codes for every verdict (`DENY_*`, `APPROVAL_*`, `ALLOW_*`);
  change-freeze and maintenance windows, quotas, rate limits, canary-first campaigns, role capacity floors, a
  deny-list, N-of-M approval pools with escalation timers.
- **Agents**: root-cause agent (cascade graph, topology), verifier agent with rollback proposals, capacity agent,
  postmortem agent (deterministic template; a model may write only the summary), schema-validated LLM planner with
  one retry then escalation.
- **Detection**: EWMA z-score and seasonal detectors beside thresholds; correlation of host incidents into rack /
  zone / PDU / DC group incidents; detector evaluation harness.
- **Audit**: Merkle checkpoints, HMAC-SHA256 signatures, external anchors, replay.
- **Scenarios**: 42 JSON scenarios with seeded regression bounds for approve-all and deny-all runs.
- **CLI**: `simulate`, `bench`, `audit verify|replay`, `postmortem`, `export-metrics`, `scenarios`, `policies`,
  `runbooks`, `faults`, `explain`; `--json` everywhere; plain-stdout dashboard; Prometheus text export.
- **Evals**: detection quality per fault type, MTTR/containment across policies, adversarial safety, a 288-run Monte
  Carlo policy sweep and a CI regression gate. `fleetgate.adversary` holds the hostile generators and the safety
  invariants.
- **Docs**: README, ARCHITECTURE, POLICY, RUNBOOKS, SCENARIOS, EVALS, two flowcharts, launch write-ups and an FAQ;
  most of it generated from the code and the recorded results.
- **Tooling**: Makefile, Dockerfile, CI matrix for Python 3.10 to 3.13 (ruff, pytest with coverage, docs check, eval
  regression gate).

### Fixed (found while testing the expansion)

- A rollback that needed approval was withdrawn the moment the plan aborted, so it never ran.
- Stacked approval requirements (disruptive action on a protected host) were merged into one pool, so a plain `sre`
  could approve work on a protected host. They are now independent pools filled by different people.
- A maintenance window did not actually re-open DISRUPTIVE work inside a freeze.
- Rack-scope runbooks were judged by the proposed host only; protected roles and the drain cap are now checked over
  every host they touch.
- A policy-denied real step was pruned and the plan carried on to `undrain_host`, un-containing a faulty host in a
  loop. A denial of a real step now stops the plan.
- Audit entries held live references to caller lists; a growing group incident broke the hash chain.
- With an HMAC key configured, entries with stripped signatures passed verification.
- A trailing `$` in a schema pattern matched before a final newline.
- Unresolved group incidents spawned per-host fixes that fought the rack-level problem.
- The EWMA detector could never flag a 1 to 0 state flip; the seasonal detector false-alarmed in its first ticks.
- p90 time-to-detect used banker's rounding instead of nearest-rank.
- Canary-first still offered `ALLOW_CANARY` when disabled; the postmortem reported the first "closed" event instead
  of the last; post-repair hosts stayed drained forever.

### Changed

- Plans run one step per verification cycle, so a destructive step takes several ticks, not one. Four 0.1.0 tests
  were updated for that, and each says why in its comment and commit message.
- Playbooks for disk, DIMM and NVMe replacement now end with `undrain_host`.
- `Risk` is kept as an alias of the new three-level `Tier`.

## 0.1.0

First release: 6 fault types, 7 runbooks, a 30-host simulator, threshold detector, heuristic and LLM planners, a
deterministic policy gate (reversible allow, destructive and protected-role approval, blast-radius cap, cooldown,
per-tick budget), a hash-chained audit log and 19 tests.
