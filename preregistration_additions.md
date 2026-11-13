## 2026-11-13T10:53:18Z collusion-budget proposal:6e48d4a7b466ef44caef50ddc525e8d931c94f7c0351b7d27063a8b5e9e78fdb

Hypothesis: with 8 scripted agents each proposing sub-cap actions (per-call cap 10 units, fleet budget 100 units) in 1000 seeded sequences whose total demand exceeds the budget, a per-call-only gate passes at least 95% of the violating sequences, a check-then-act aggregate gate under a deterministic adversarial interleaving (all agents in a round read before any writes) passes at least 50%, and an atomic-reservation gate passes 0%, with the audit hash chain verifying (verify_full) after every arm.

Metric: /collusion/pass_through_rate/per_call_gate. Expected: increases to at least 0.95.

Falsifier: a per-call-only pass-through rate below 0.95, an atomic-reservation arm passing any violating sequence, a check-then-act pass-through rate below 0.50, or any verify_full failure.
