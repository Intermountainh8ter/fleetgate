# r/sre post

Suggested title: **I built a policy gate that LLM/heuristic incident agents can't talk their way past (simulator, MIT,
looking for critique of the tiering)**

Check the subreddit's self-promotion rules before posting; this is written to lead with the design question rather
than the repo. Put the link at the end.

---

I've been thinking about the bit most "agentic ops" demos hand-wave: what's the contract between the thing that
*suggests* a remediation and the thing that *does* it?

fleetgate is my attempt at a small, testable answer, on a simulated bare-metal fleet:

- Agents (LLM-backed or a plain playbook) can only propose a runbook **id** from a closed catalogue. Nothing they
  emit is executable. Matching is exact, so `"drain_host "` and a Cyrillic-a lookalike are just unknown runbooks.
- A deterministic default-deny gate returns ALLOW / NEEDS_APPROVAL / DENY with a reason code. Order: unknown
  runbook/host, deny-list, freeze, preconditions, cooldown, tick budget, rate limit, quotas, blast radius (drained
  fraction), role capacity floor, canary-first, then approval, then allow. Approval never overrides a DENY.
- Runbooks are tiered REVERSIBLE / DISRUPTIVE / DESTRUCTIVE. Destructive needs N-of-M approvers; touching a protected
  role (db primary, validator) stacks a second approver pool, filled by different people. A rack-wide runbook is
  judged by every host it touches, not just the one named.
- After every action a verifier re-reads metrics; a failed probe proposes the rollback partner *through the same
  gate* and pages.
- Everything lands in a hash-chained audit log (Merkle checkpoints, optional HMAC, external anchors), and a
  postmortem is generated from the log alone.

How I tried to avoid fooling myself: a seeded fuzzer throws typosquats, spoofed hosts, oversized plans and nested JSON
at every bundled policy, and I mutation-tested the fuzzer by breaking the gate nine ways (destructive without
approval, blast radius off, deny-list ignored, ...). All nine get caught. Writing the tests turned up real design
bugs: my first approval design merged the pools, so a plain `sre` could approve a reboot of a protected host; a
denied step in a plan used to be skipped, so a later `undrain_host` un-contained a faulty host in a loop.

<!-- BEGIN:numbers -->
- 28 fault types plus 3 rack-level ones
- 32 runbooks in 3 risk tiers
- 42 scenarios
- 5 policies
- 23 reason codes
- 2460 hostile-planner runs (104828 gate evaluations) with 0 safety violations
- 288 Monte Carlo policy runs
- 778 tests at 99.2% line+branch coverage
<!-- END:numbers -->

**What this is not:** real. It's a simulator. Faults are injected steps/ramps/intermittents on Gaussian noise; fixes
clear after a fixed delay; the humans are a latency model; my thresholds and my faults were written by the same
person, so the threshold detector's perfect score says nothing about real SMART/BMC data. The README leads with that
and has a limitations section. The Monte Carlo result (the drain cap dominates MTTR; extra sign-offs cost a fraction of
a tick) is a statement about my model's assumptions.

Questions I'd actually like answered by people who run fleets:

1. Is REVERSIBLE / DISRUPTIVE / DESTRUCTIVE the right granularity, or do you split on something else (blast radius,
   data loss, who is paged)?
2. Where would you put the line on a rack-wide action that touches one protected host?
3. What would you want in a verification probe beyond "metric X is back under Y"?
4. Which failure modes of an approval flow (fatigue, rubber-stamping, latency) would you model first?

MIT, zero runtime deps, everything runs offline. Repo link in a comment or at the end of the post, as the sub's rules
allow.
