# LinkedIn post

Plain text, ready to paste. Put the repository link in the first comment (LinkedIn suppresses posts with links in the
body). The bullet list under "numbers" is regenerated from real runs by `scripts/gen_docs.py`.

---

Most "AI agent fixes your outage" demos skip the part where someone asks what stops it from doing something stupid at
3am.

I built a small project around that question. fleetgate is multi-agent incident response for a simulated bare-metal
fleet with one rule: agents can only PROPOSE runbooks from a closed catalogue. A deterministic, default-deny policy
gate decides ALLOW, NEEDS_APPROVAL or DENY for every proposal, with a machine-readable reason code. Every detection,
verdict, vote and verification goes into a hash-chained audit log you can verify, replay and turn into a postmortem.

What that looks like in practice:
- A planner (heuristic or LLM) names runbook ids. A typosquat like "drain_host " with a trailing space or a Unicode
  lookalike is simply an unknown runbook.
- Reversible actions on unprotected hosts run. Destructive ones need N-of-M approvers; touching a protected host
  stacks a second pool filled by different people. Approval can never override a DENY.
- Blast-radius cap, cooldowns, per-tick budgets, change freezes, canary-first campaigns, capacity floors.
- A verifier re-reads metrics after every action and rolls back through the same gate when probes fail.

The part I care most about: the safety claims are tested, not asserted. A seeded fuzzer throws hostile plans at every
policy and approver, and I mutation-checked the fuzzer by breaking the gate nine different ways to prove it notices.
Writing the tests found real bugs in my own design, for example a stacked-approval rule that let a plain SRE approve
work on a database primary.

numbers (from real runs):

<!-- BEGIN:numbers -->
- 28 fault types plus 3 rack-level ones
- 32 runbooks in 3 risk tiers
- 42 scenarios
- 5 policies
- 23 reason codes
- 2460 hostile-planner runs (104828 gate evaluations) with 0 safety violations
- 288 Monte Carlo policy runs
- 779 tests at 99.2% line+branch coverage
<!-- END:numbers -->

The honest caveat: it is a simulator. The faults are injected, the noise is Gaussian, the humans are a latency model,
and the detector thresholds were written by the same person who wrote the faults. It demonstrates that the plumbing
and the safety logic hold, not that this would survive contact with real BMC telemetry. The README says so on the
first screen and has a limitations section.

MIT licensed, zero runtime dependencies, tests and evals run offline. I would love critique from people who run real
fleets: where would you draw the tier boundaries differently?

#SRE #IncidentResponse #AIAgents #Reliability #OpenSource
