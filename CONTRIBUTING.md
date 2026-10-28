# Contributing

Thanks for looking. fleetgate is a small project with strong opinions about safety; the quickest way to get a change
merged is to keep the opinions intact.

## Set up

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # pytest, pytest-cov, ruff; add ,llm for the optional Anthropic SDK
make check                         # ruff + tests with coverage + generated-docs check
```

Python 3.10 to 3.13 are supported and tested in CI. There are no required runtime dependencies and there must not be
any: new functionality uses the standard library (see `schema.py` for the validator we wrote instead of depending on
`jsonschema`). Tests and evals run offline with no API key.

## Rules that are not negotiable

1. **Agents propose, the gate disposes.** Nothing an agent (or an LLM, or an approver) returns may become executable
   or bypass `Policy.evaluate`. A change that adds a second path from a proposal to the fleet will be rejected.
2. **Default-deny, fail closed.** A new gate rule returns a DENY on any doubt, carries a `Reason` code and a
   `REASON_GUIDE` entry (meaning and fix), and is added to `docs/diagrams/troubleshooting.mmd`. The tests check all
   three.
3. **Approval never overrides a DENY.** Hard limits are evaluated before approval is requested.
4. **Every number in the docs comes from a real run.** The README, `docs/POLICY.md`, `RUNBOOKS.md`, `SCENARIOS.md` and
   the launch posts are generated (`python scripts/gen_docs.py`) from the code and from `evals/results/`. Never
   type a statistic by hand. Be explicit that the simulator is idealised wherever results appear.
5. **No stubs, no placeholder markers, no silent catch-all.** If a feature is not finished, leave it out.

## Making a change

- **Tests first for behaviour changes.** `tests/` mirrors the modules. Anything touching the gate must keep
  `tests/test_policy_fuzz.py` green; if you add a safety invariant, add it to `fleetgate.adversary.check_invariants`
  and prove it bites with a deliberately broken gate (mutate the code, watch the fuzzer fail, revert).
- **Style.** `ruff check .` must pass (line length 120). Type-annotate public functions. Keep `from __future__ import
  annotations` at the top of modules so 3.10 syntax stays valid.
- **New fault / runbook / scenario / policy / approver / planner / detector**: see "Extending" in
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Runbooks and policies are JSON validated at load; scenarios live in
  `scenarios/` and carry recorded bounds (`python scripts/calibrate_expectations.py --write NAME`, review the numbers
  before committing them).
- **Changed behaviour moves numbers.** Re-run `python evals/run_evals.py`, then `python scripts/record_quality.py`,
  then `python scripts/gen_docs.py`, and commit the regenerated results with the change. If the regression gate
  fails for a reason you understand, `python evals/regression_gate.py --update-baseline` records the new baseline;
  say why in the commit message.
- **Diagrams.** Edit `docs/diagrams/*.mmd` and run `scripts/render_diagrams.sh` (needs Node and a Chromium; set
  `MMDC` to a local `mmdc` to skip the npx download). Then `python scripts/gen_docs.py` to refresh `FLOWCHARTS.md`.

## Commit messages

Say what changed and why. If you edited an existing test, say why the *interface* legitimately changed; a test is not
something to bend to fit the code.

## Reporting a security problem

A way to make the gate allow something it should not (a lookalike runbook id, an approval that overrides a DENY, a
plan that executes without a verdict) is the most valuable bug there is. Please open an issue with a minimal
reproduction, or email the maintainer if you would rather not post it publicly.

By contributing you agree your work is released under the MIT license.

## Publishing to PyPI

Maintainer steps. Nothing is published until you do them; the workflow in `.github/workflows/publish.yml`
only runs when a GitHub Release is published.

1. On pypi.org, add a *pending trusted publisher* for the project name `fleetgate`: owner `Intermountainh8ter`,
   repository `fleetgate`, workflow `publish.yml`, environment `pypi`. (No API token is needed or stored.)
2. In this repository's Settings, create an environment named `pypi` (optionally with required reviewers).
3. Make sure `version` in `pyproject.toml` is the version you want, and that CI is green on `main`.
4. Create a GitHub Release whose tag is `v<version>` (for example `v0.2.0`). The workflow builds the
   sdist and wheel, runs `twine check`, and uploads them.
5. A PyPI version can never be re-uploaded, so check the built files first with `python -m build`
   and `twine check dist/*`.
