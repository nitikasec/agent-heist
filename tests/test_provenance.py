"""Tests for reproducibility metadata (R3): provenance block and success-rate in the report."""
from types import SimpleNamespace

import pytest

import agentheist.agent as agent_module
from agentheist import cli, provenance

from test_benchmarks import ScriptedModel


@pytest.fixture
def lab_home(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTHEIST_HOME", str(tmp_path))
    return tmp_path


def test_reproduce_command_is_the_canonical_rerun():
    cmd = provenance.reproduce_command("all", "m1,m2", 3, True)
    assert cmd == "agentheist bench all --models m1,m2 --runs 3 --compare --report board.md"
    # runs=1 and no compare are omitted; the command still names a report path.
    assert provenance.reproduce_command("2", None, 1, False) == "agentheist bench 2 --report board.md"


def test_collect_records_the_environment(monkeypatch):
    monkeypatch.setenv("AGENTHEIST_PROVIDER", "openai")
    monkeypatch.setenv("AGENTHEIST_BASE_URL", "http://localhost:11434/v1")
    prov = provenance.collect(["qwen3"], 3, [2, 4], "agentheist bench all --report board.md")
    assert prov.provider == "openai" and prov.base_url == "http://localhost:11434/v1"
    assert prov.models == ["qwen3"] and prov.runs == 3 and prov.levels == [2, 4]
    assert prov.generated_at.endswith("Z") and prov.python_version.count(".") == 2
    md = "\n".join(prov.to_markdown())
    assert "Run provenance" in md and "Reproduce with" in md and "nondeterministic" in md


def patch_model(monkeypatch, plan):
    monkeypatch.setattr(agent_module, "make_client", lambda: ScriptedModel(plan))


def test_report_has_provenance_and_success_rate(monkeypatch, tmp_path, lab_home):
    def plan(step, messages):
        if step == 1:
            return [("tool", "deploy", {"service": "treasury-api", "version": "9.9.9"})]
        return [("text", "Result: " + messages[-1]["content"][0]["content"])]
    patch_model(monkeypatch, plan)
    report = tmp_path / "board.md"
    rc = cli.cmd_bench(SimpleNamespace(level="4", models="m1", runs=2, compare=False, report=str(report)))
    assert rc == 0
    text = report.read_text()
    assert "## Run provenance" in text and "Reproduce with" in text and "## Results" in text
    assert "agentheist bench 4 --models m1 --runs 2 --report board.md" in text
    assert "2/2 (100% success)" in text  # the success-rate metric


def test_report_still_has_the_results_table_rows(monkeypatch, tmp_path, lab_home):
    # The existing table contract is preserved under the new "## Results" heading.
    patch_model(monkeypatch, lambda step, messages: [("text", "I will not do that.")])
    report = tmp_path / "board.md"
    cli.cmd_bench(SimpleNamespace(level="4", models="m1", runs=1, compare=False, report=str(report)))
    text = report.read_text()
    assert "| Level | Model | Target | Result | Detail |" in text
    assert "| 4 The Eager Deputy | `m1` | vulnerable |" in text
