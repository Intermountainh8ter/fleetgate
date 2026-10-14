# FAQ: the hard questions

Honest answers to the questions a sceptical SRE would ask. Numbers come from real runs and are generated.

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

## Is this real?

No. It is a **simulator**. The fleet, the faults, the noise, the fixes and the humans are all modelled. Nothing talks
to a BMC, IPMI, a scheduler or a ticketing system. What it shows is that a particular *architecture* (agents propose,
a deterministic gate decides, an audit log records) can be made to hold under hostile input, and that you can test that
claim. What it cannot show is that the detectors, thresholds or playbooks would work on your hardware.

## Why is a perfect detection score not impressive?

Because the thresholds and the faults were written by the same person against the same simulator. The threshold
detector scoring perfectly is a statement about the simulator. The interesting results are the *relative* ones (an
EWMA baseline falls apart under diurnal load, a seasonal baseline does not, EWMA misses slow ramps) and even those
depend on the simulator's Gaussian noise. Run the detectors on recorded telemetry before believing any of it.

## Why a deterministic gate instead of a guardrail model or a smarter prompt?

Because I want to be able to *prove* things about it. A deterministic gate is a pure function of the proposal, the
fleet state and the policy history; you can enumerate its rules, fuzz it, mutation-test it and replay it from an audit
log. A guardrail model has the same failure mode as the thing it guards: it can be talked into things. The LLM is
allowed to be wrong; it is not allowed to be *in the loop of enforcement*.

## What can the LLM actually do here?

Three things, all non-executable: write the one-sentence triage summary, write the root-cause narrative, and (if you
choose the LLM planner) propose a JSON plan naming catalogue ids. Severity, blast radius, root-cause hypothesis and
every verdict are deterministic. A malformed, oversized, typosquatted or out-of-scope plan becomes an empty plan and a
page. The Anthropic-backed paths have only been exercised with scripted stand-ins in this repository's tests.

## Isn't this just Rundeck / StackStorm / Ansible with extra steps?

Those execute runbooks and are excellent at it. fleetgate is about the decision layer *in front of* execution when the
requester is an untrusted agent: closed catalogue, tiering, N-of-M approval pools, blast-radius and capacity floors,
canary-first, verification and rollback through the same gate, and an audit log designed to be checked. You could put
the same gate in front of any of those executors; here the executor is a simulator so that the whole thing is
testable.

## Why not just use an approval click for everything?

Approval fatigue is real: if every action needs a human, humans rubber-stamp. Reversible actions on unprotected hosts
run on their own; humans are asked about the things that can hurt (destructive, disruptive, protected roles), and
the gate has already enforced the limits a tired human would forget (drain cap, capacity floor, cooldown).

## Can approval override a DENY?

No, and a test checks it. Approval is only requested after every hard limit passed, and an approved step is
re-evaluated by the gate when it is about to run: if a freeze started while it waited, it is denied.

## How do you know the safety tests would notice a broken gate?

I broke the gate on purpose nine ways (destructive allowed, blast radius off, deny-list ignored, typosquats stripped,
protected role ignored, tick budget off, orchestrator skipping approval, preconditions skipped, maintenance window
allowing destructive work) and checked that the fuzzer fails for each. See `docs/ARCHITECTURE.md`.

## What did writing the tests find?

Real bugs in my own design: a rollback that needed approval was withdrawn before it could run; stacked approval
requirements were merged so a plain SRE could approve work on a protected host; a denied step was skipped and a later
`undrain_host` un-contained a faulty host in a loop; audit entries held references to lists that kept growing and broke
the hash chain; stripped HMAC signatures passed verification. All are fixed and have regression tests; they are listed
in the CHANGELOG.

## Is the audit log tamper-proof?

No: tamper-*evident*. A hash chain detects edits, deletions and reordering. HMAC signatures detect a rewrite by anyone
without the key. A full rewrite by someone with the key, or a truncation, is only detected against an external anchor
(a file of Merkle roots you keep out of the writer's reach). Each of those attacks has a test.

## Was AI used to build this?

Yes. This repository was built with an AI coding assistant working in long sessions: it wrote most of the code, the
tests and the documentation and ran the tests and evals, and the git history shows it. The author, Ammon Jackson,
chose the design rule and the scope and owns the result. Do not trust a paragraph on who typed what: the evidence is
that the tests, the mutation check on the fuzzer and the evals can be re-run (`make check`, `python evals/run_evals.py`)
and that every number in the docs is generated from them. Read the code and the tests, and tell me what is wrong.

## What would you do next?

Replay real telemetry through the detectors and measure the false-positive rate; add an executor adapter behind the
gate for one real system with a dry-run first; model approver fatigue; broaden the fuzzer to the approval protocol
itself. Not done: any of that.

## License?

MIT.
