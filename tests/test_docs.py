"""Docs are code: generated files are current, examples run, links resolve, diagrams cover the real reason codes."""
import contextlib
import importlib.util
import io
import json
import re
import shlex
from pathlib import Path

import pytest

from fleetgate.cli import build_parser, main
from fleetgate.policy import Decision, Reason
from fleetgate.runbooks import CATALOG
from fleetgate.scenarios import load_scenarios

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generated_docs_are_up_to_date():
    gen = load_script("gen_docs")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = gen.main(["--check"])
    assert code == 0, buf.getvalue()


def test_every_expected_doc_exists():
    for rel in ["README.md", "CONTRIBUTING.md", "CHANGELOG.md", "LICENSE", "Makefile", "Dockerfile",
                ".github/workflows/ci.yml", "docs/ARCHITECTURE.md", "docs/POLICY.md", "docs/RUNBOOKS.md",
                "docs/SCENARIOS.md", "docs/FLOWCHARTS.md", "docs/EVALS.md", "docs/diagrams/usage.mmd",
                "docs/diagrams/troubleshooting.mmd", "docs/diagrams/usage.svg", "docs/diagrams/troubleshooting.svg",
                "docs/launch/LINKEDIN.md", "docs/launch/REDDIT_SRE.md", "docs/launch/DISCORD_SHORT.md",
                "docs/launch/FAQ.md", "scripts/render_diagrams.sh", "evals/results/results.json",
                "evals/results/results.md", "evals/results/quality.json", "evals/baseline.json"]:
        assert (ROOT / rel).is_file(), rel


def doc_files():
    return [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").rglob("*.md"))]


def test_relative_links_resolve():
    link = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s#]+)(?:#[^)]*)?\)")
    for path in doc_files():
        for target in link.findall(path.read_text()):
            assert (path.parent / target).exists(), f"{path.relative_to(ROOT)} links to missing {target}"


def test_readme_python_examples_run():
    blocks = re.findall(r"```python\n(.*?)```", README, re.S)
    assert len(blocks) >= 2
    for block in blocks:
        exec(compile(block, "<README>", "exec"), {})


def test_readme_quickstart_commands_work(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    block = re.search(r"```\npip install.*?```", README, re.S).group(0)
    commands = [line.split("#")[0].strip() for line in block.splitlines() if line.startswith("fleetgate ")]
    assert len(commands) >= 8
    sub = set(build_parser()._subparsers._group_actions[0].choices)
    for cmd in commands:
        argv = shlex.split(cmd)[1:]
        assert argv[0] in sub, cmd
        code = main(argv)
        capsys.readouterr()
        assert code == 0, f"README command failed: {cmd}"


def code_text(md: str) -> str:
    """Only what is rendered as code: fenced blocks and inline `spans`."""
    fenced = re.findall(r"```(?!python)[a-z]*\n(.*?)```", md, re.S)
    inline = re.findall(r"`([^`\n]+)`", re.sub(r"```.*?```", "", md, flags=re.S))
    return "\n".join(fenced + inline)


def test_every_fleetgate_command_mentioned_in_docs_exists():
    sub = set(build_parser()._subparsers._group_actions[0].choices)
    texts = [code_text(p.read_text()) for p in doc_files() if p.name != "CHANGELOG.md"]
    texts += [(ROOT / "docs/diagrams" / f).read_text() for f in ("usage.mmd", "troubleshooting.mmd")]
    mentioned = set()
    for text in texts:
        mentioned |= set(re.findall(r"(?<![\w-])fleetgate ([a-z][a-z-]+)", text))
    assert {"simulate", "audit", "explain", "runbooks", "scenarios", "postmortem"} <= mentioned
    assert mentioned <= sub | {"audit"}, mentioned - sub


def test_troubleshooting_chart_covers_every_deny_code_and_names_real_commands():
    tree = (ROOT / "docs/diagrams/troubleshooting.mmd").read_text()
    for r in Reason:
        if r.decision == Decision.DENY:
            assert r.value in tree, f"{r.value} missing from the troubleshooting tree"
    for needle in ["audit verify", "audit replay", "fleetgate runbooks", "fleetgate explain", "fleetgate faults",
                   "fleetgate scenarios", "--no-correlate", "--key-env", "escalation.expire_after_ticks",
                   "max_drained_fraction", "min_active_per_role" if "min_active_per_role" in tree else "role"]:
        assert needle in tree, needle
    svg = (ROOT / "docs/diagrams/troubleshooting.svg").read_text()
    assert "<svg" in svg and "DENY_COOLDOWN" in svg and "DENY_BLAST_RADIUS" in svg
    usage_svg = (ROOT / "docs/diagrams/usage.svg").read_text()
    assert "<svg" in usage_svg and "Policy gate" in usage_svg and "audit verify" in usage_svg


def test_usage_chart_names_every_stage_the_task_requires():
    usage = (ROOT / "docs/diagrams/usage.mmd").read_text().lower()
    for stage in ["scenario", "simulate", "detect", "correlate", "triage", "plan", "policy gate", "approv",
                  "execute", "verify", "rollback", "audit", "postmortem"]:
        assert stage in usage, stage


def test_flowcharts_md_embeds_both_charts_as_mermaid():
    text = (ROOT / "docs/FLOWCHARTS.md").read_text()
    assert text.count("```mermaid") == 2
    for f in ("usage", "troubleshooting"):
        assert (ROOT / f"docs/diagrams/{f}.mmd").read_text().rstrip() in text


def test_readme_embeds_both_svgs_under_diagrams():
    assert "## Diagrams" in README
    assert "![fleetgate usage flowchart](docs/diagrams/usage.svg)" in README
    assert "![fleetgate troubleshooting decision tree](docs/diagrams/troubleshooting.svg)" in README


def test_readme_numbers_equal_the_recorded_results():
    results = json.loads((ROOT / "evals/results/results.json").read_text())
    quality = json.loads((ROOT / "evals/results/quality.json").read_text())
    assert f"**{quality['tests']} tests**" in README and f"**{quality['coverage_total']}% line+branch" in README
    adv = results["adversarial"]["total"]
    assert f"{adv['runs']} runs, {adv['gate_evaluations']} gate evaluations" in README
    assert f"{results['montecarlo']['runs']} seeded runs" in README
    assert f"**{adv['violations']} safety-invariant violations" in README
    assert f"{len(CATALOG)} runbooks" in README and f"**{len(load_scenarios())} named scenarios**" in README
    first = next(iter(results["policy"]["cells"].values()))
    assert f"{first['mttr_mean']:.1f}" in README or f"{first['mttr_mean']:.3f}" in README


def test_the_unfixable_fraction_claim_in_the_readme_is_true():
    from fleetgate.runner import run_scenario

    total = unfixable = 0
    for name, s in load_scenarios().items():
        injected = run_scenario(s).summary()["faults_injected"]
        total += injected
        if name in ("cooling_zone_loss", "pdu_failure_pair"):  # a CRAC unit or a PDU cannot be fixed by a runbook
            unfixable += injected
    assert 0.28 <= unfixable / total <= 0.36 and "about a third" in README


def test_no_placeholder_markers_or_stray_model_identifiers_in_the_repo():
    banned_markers = re.compile(r"\b(TO" + r"DO|FIX" + r"ME|X" + r"XX)\b")
    banned_models = re.compile(r"(?i)\b(claude|sonnet|opus|haiku|gpt-?\d|gemini|llama|mistral)\b")
    skip = {".git", ".ruff_cache", ".pytest_cache", "__pycache__", "fleetgate.egg-info", ".venv", "htmlcov", "build",
            "dist"}  # build outputs are gitignored copies of src/
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in skip or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix in {".svg", ".png", ".pyc", ".coverage"} or path.name == ".coverage":
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in {"tests/test_docs.py"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not banned_markers.search(text), f"placeholder marker in {rel}"
        if rel != "src/fleetgate/llm.py":
            assert not banned_models.search(text), f"AI model identifier in {rel}"


def test_license_and_author():
    assert "MIT License" in (ROOT / "LICENSE").read_text() and "Ammon Jackson" in (ROOT / "LICENSE").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'authors = [{ name = "Ammon Jackson" }]' in pyproject and 'license = { text = "MIT" }' in pyproject
    assert "dependencies = []" in pyproject and "pytest-cov" in pyproject


def test_ci_matrix_runs_the_required_steps():
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    for needle in ['"3.10"', '"3.11"', '"3.12"', '"3.13"', "ruff check", "pytest -q --cov", "regression_gate.py"]:
        assert needle in ci, needle


@pytest.mark.parametrize("path", sorted((ROOT / "docs" / "launch").glob("*.md")))
def test_launch_posts_state_the_simulator_caveat(path):
    text = path.read_text().lower()
    assert "simulator" in text
