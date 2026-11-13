## 2026-11-13T10:53:18Z collusion-budget proposal:6e48d4a7b466ef44caef50ddc525e8d931c94f7c0351b7d27063a8b5e9e78fdb

Hypothesis: with 8 scripted agents each proposing sub-cap actions (per-call cap 10 units, fleet budget 100 units) in 1000 seeded sequences whose total demand exceeds the budget, a per-call-only gate passes at least 95% of the violating sequences, a check-then-act aggregate gate under a deterministic adversarial interleaving (all agents in a round read before any writes) passes at least 50%, and an atomic-reservation gate passes 0%, with the audit hash chain verifying (verify_full) after every arm.

Metric: /collusion/pass_through_rate/per_call_gate. Expected: increases to at least 0.95.

Falsifier: a per-call-only pass-through rate below 0.95, an atomic-reservation arm passing any violating sequence, a check-then-act pass-through rate below 0.50, or any verify_full failure.

## 2026-11-13T10:57:38Z audit-overhead proposal:8f7f4250a2339917a0e0eeaa330fdd58f41348a266613a1e2c6d41719721e640

Hypothesis: serialized audit size per entry stays within 20% between 1,000 and 100,000 appended entries (bytes per entry roughly constant) and verify_full performs a hash-operation count that scales linearly with entries (ratio of per-entry verify operations between 100,000 and 1,000 entries at most 1.1), with verify_full passing at every scale.

Metric: /audit_overhead/bytes_per_entry_ratio_100k_over_1k. Expected: stays within 0.8 to 1.2 (about 1.0).

Falsifier: bytes-per-entry ratio outside 0.8-1.2, per-entry verify operation ratio above 1.1, or any verify_full failure at any scale.
