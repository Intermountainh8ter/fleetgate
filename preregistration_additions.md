## 2026-11-13T10:53:18Z collusion-budget proposal:6e48d4a7b466ef44caef50ddc525e8d931c94f7c0351b7d27063a8b5e9e78fdb

Hypothesis: with 8 scripted agents each proposing sub-cap actions (per-call cap 10 units, fleet budget 100 units) in 1000 seeded sequences whose total demand exceeds the budget, a per-call-only gate passes at least 95% of the violating sequences, a check-then-act aggregate gate under a deterministic adversarial interleaving (all agents in a round read before any writes) passes at least 50%, and an atomic-reservation gate passes 0%, with the audit hash chain verifying (verify_full) after every arm.

Metric: /collusion/pass_through_rate/per_call_gate. Expected: increases to at least 0.95.

Falsifier: a per-call-only pass-through rate below 0.95, an atomic-reservation arm passing any violating sequence, a check-then-act pass-through rate below 0.50, or any verify_full failure.

## 2026-11-13T10:57:38Z audit-overhead proposal:8f7f4250a2339917a0e0eeaa330fdd58f41348a266613a1e2c6d41719721e640

Hypothesis: serialized audit size per entry stays within 20% between 1,000 and 100,000 appended entries (bytes per entry roughly constant) and verify_full performs a hash-operation count that scales linearly with entries (ratio of per-entry verify operations between 100,000 and 1,000 entries at most 1.1), with verify_full passing at every scale.

Metric: /audit_overhead/bytes_per_entry_ratio_100k_over_1k. Expected: stays within 0.8 to 1.2 (about 1.0).

Falsifier: bytes-per-entry ratio outside 0.8-1.2, per-entry verify operation ratio above 1.1, or any verify_full failure at any scale.

## 2026-11-14T11:06:55Z omission-detection proposal:0a23b1d2304d9a50d40a793fda4577ec9b6e4e23257801a0daa45a290def0dc6

Hypothesis: on 1000 seeded SIMULATED logs per omission type (k in 1..5 decisions dropped), verify_full with no anchors detects 100% of middle deletions but 0% of never-written decisions and of tail truncations; adding a gate-side decision counter (issued decisions vs decision entries in the log) raises detection of both to 100%.

Metric: /omission/detection_rate/tail_truncation_chain_only. Expected: decreases to at most 0.10.

Falsifier: a chain-only tail-truncation detection rate above 0.10, a chain-only middle-deletion rate below 1.0, or a counter-augmented arm detecting fewer than 100% of any omission type.

## 2026-11-15T11:24:38Z gate-arg-mutation proposal:de3d1c8d253bffa069dfa7300353adc15b5b77b3458802d920c4725da4a7ed98

Hypothesis: across at least 400 SIMULATED mutated variants (case, whitespace, Unicode, type-confusion and repeated-id mutations of runbook and host arguments) of calls Policy.evaluate canonically denies, Policy.evaluate returns ALLOW or NEEDS_APPROVAL for none of them (overall pass rate 0, Wilson 95% upper bound below 0.01 at n=480), because ids are exact-match lookups that fail closed to DENY or exceptions to INTERNAL_ERROR.

Metric: /mutation/pass_rate/overall. Expected: stays at 0.0; Wilson 95% upper bound below 0.01.

Falsifier: any mutated variant of a canonically denied call that receives ALLOW or NEEDS_APPROVAL, i.e. an overall pass rate above 0.

## 2026-11-15T11:28:30Z tool-drift-fingerprint proposal:d17044fca44f447a622e35655c39b3d57516067f577c5df258245bd88ae65d32

Hypothesis: over at least 400 SIMULATED semantic-drift mutations (same schema shape, changed description wording) of a baselined tool, a canonical-hash fingerprint gate passes none (pass rate 0, Wilson 95% upper bound below 0.01 at n=480), a schema-validation-only gate passes all of them, and the hash gate passes 100% of tools poisoned from their first listing while flagging a nonzero share of benign rewordings as drift.

Metric: /drift/pass_rate/semantic_post_baseline. Expected: stays at 0.0 for the hash-fingerprint gate; Wilson 95% upper bound below 0.01.

Falsifier: any post-baseline semantic-drift variant that the hash-fingerprint gate passes (pass rate above 0), or a first-listing-poison pass rate below 1.0 for the hash gate.

## 2026-11-16T12:15:30Z gate-interleave proposal:3487cd064f2e725af3e349f7e27b782f7c8b9f011598332ebf31610534b2207e

Hypothesis: on the real fleetgate Policy with the default config, in 500 seeded SIMULATED rounds where 2 to 8 agents each propose a drain of a distinct host in the same role, sequential evaluate-then-execute never breaches the role capacity floor or max drained fraction (breach rate 0), while the stale-read interleaving, where every agent evaluates before any executes, approves a joint set that breaches the capacity floor in at least half of rounds whose total demand exceeds the floor headroom; a reservation-style re-check at execute time restores a breach rate of 0.

Metric: /real_gate_interleave/breach_rate/stale_read. Expected: increases to at least 0.50; sequential and re-check arms stay at 0.0.

Falsifier: a stale-read breach rate below 0.50, any breach in the sequential or execute-time re-check arm, or any verify_full failure on the audit log.
