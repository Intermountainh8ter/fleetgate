# Evals

> **The simulator is idealised.** Faults are injected step/ramp/intermittent changes on Gaussian noise, a fix clears a
> fault after a fixed delay, thresholds were written by the same author as the faults, and humans are a latency
> model. These evals check that the plumbing, the gate and the detectors behave as designed on a model of a fleet.
> They are not evidence about real telemetry, operators or outage rates.

```
python evals/run_evals.py                        # everything, writes evals/results/results.{md,json} (~6 min)
python evals/run_evals.py --quick                # CI size
python evals/run_evals.py --section adversarial  # detection | policy | adversarial | montecarlo
python evals/regression_gate.py                  # the CI gate (~2 min)
python evals/regression_gate.py --update-baseline  # record new baselines (review the diff first)
```

Every number in the README comes from `evals/results/results.json` through `scripts/gen_docs.py`.

## Sections

**Detection** (`detection_eval.py`, `fleetgate.deteval`). For each of the fault types, a fresh 20-host fleet warms up
healthy for 150 ticks (plus a seeded 0-47 extra so a diurnal fault lands at different phases), one fault is injected
on one host, and the detector watches 40 more ticks. A detection on that host about a metric the fault (or its
cascade) perturbs is a true positive; anything else is a false positive. Recall is detected / runs, precision is
TP / (TP + FP), time-to-detect is ticks from injection to the first true positive. Three detectors (threshold, EWMA,
seasonal) under two load regimes (flat, +-40% diurnal), plus false alarms on fault-free fleets.

**MTTR and containment** (`policy_eval.py`). Every bundled scenario under every bundled policy with three approver
models: instant, a latency model of humans (`LatencyApprover`: first approval after 2 ticks, +1 per extra approver)
and nobody. Resolved means the fault was fixed; contained means the host was drained but the fault remains.

**Adversarial safety** (`adversarial_eval.py`). Hostile planners (`FuzzPlanner`, `AdversarialPlanner`, and raw-text
attacks on `LLMPlanner`) against every policy and approver; `check_invariants` must find zero violations and no
exception may escape the orchestrator. The LLM-text rows are stopped by the parser before the gate, so they test the
parser.

**Monte Carlo policy sweep** (`montecarlo_eval.py`). 36 policy configurations (drain cap x destructive sign-offs x
actions per tick x canary-first) face the same seeded storms of ten mostly drain-requiring faults. Axes: censored
MTTR (an unfixed fault counts the ticks it stayed exposed, so a policy cannot look fast by never fixing things), peak
drained fraction (capacity exposure), and human sign-offs per risky action. A configuration is on the Pareto front if
no other is at least as good on all three and better on one.

## Regression gate

`evals/baseline.json` holds the numbers recorded from a quick run. The gate fails on any safety violation or
exception (zero tolerance), on any scenario whose recorded `expect` bounds no longer hold, and when detection recall
or F1, resolve rate or MTTR drift outside the tolerances stored in the baseline.

## What would change my mind

If the same detectors run on recorded BMC/SMART data, the first thing I expect to see is the threshold detector losing
its perfect score. The seasonal and EWMA comparisons are only as good as the simulator's noise model, which is
Gaussian and heteroscedastic with load, nothing more.
