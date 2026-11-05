"""Tests for the standards mapping (R4): completeness, sourcing, docs sync, and the report command."""
import re
from pathlib import Path
from types import SimpleNamespace

from agentheist import cli, owasp
from agentheist.levels import LEVELS

DOCS = Path(__file__).resolve().parents[1] / "docs" / "OWASP_MAPPING.md"
LLM_CODE = re.compile(r"^LLM\d{2}:2025$")


def test_every_level_has_a_mapping():
    assert set(owasp.MAPPINGS) == set(LEVELS)
    for n, m in owasp.MAPPINGS.items():
        assert m.categories and m.weakness and m.control


def test_every_category_has_a_known_source_and_wellformed_code():
    for m in owasp.MAPPINGS.values():
        for c in m.categories:
            assert c.framework in owasp.SOURCES and c.url.startswith("https://")
            if c.framework == owasp.LLM_TOP10:
                assert LLM_CODE.match(c.code), c.code
            else:
                # Agentic/MCP threats are named verbatim; no code is invented.
                assert c.code == ""


def test_known_mappings_are_correct():
    # Spot-check the anchor mappings against their sources.
    assert owasp.for_level(2).categories[0].code == "LLM01:2025"            # prompt injection
    assert owasp.for_level(4).categories[0].code == "LLM06:2025"            # excessive agency
    assert any(c.title == "Confused Deputy Problem" for c in owasp.for_level(4).categories)
    assert any(c.title == "Token Passthrough" for c in owasp.for_level(3).categories)
    assert any(c.title == "Supply Chain" for c in owasp.for_level(5).categories)


def test_docs_are_in_sync_with_the_module():
    text = DOCS.read_text()
    assert owasp.overview_table() in text
    for n in owasp.MAPPINGS:
        assert owasp.level_markdown(n).strip() in text


def test_cmd_report_prints_a_level(capsys):
    rc = cli.cmd_report(SimpleNamespace(level="4", report=None))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Level 4" in out and "LLM06:2025 Excessive Agency" in out
    assert "Confused Deputy Problem" in out and "genai.owasp.org" in out


def test_cmd_report_all_and_markdown(capsys, tmp_path):
    report = tmp_path / "levels.md"
    rc = cli.cmd_report(SimpleNamespace(level="all", report=str(report)))
    out = capsys.readouterr().out
    assert rc == 0 and report.exists()
    for n in owasp.MAPPINGS:
        assert f"Level {n}" in out
    text = report.read_text()
    assert "LLM01:2025 Prompt Injection" in text and "## Agent Heist" not in text
    assert text.startswith("# Agent Heist — level security reports")


def test_cmd_report_needs_no_model(capsys):
    # The report is static: it must work with no provider configured at all.
    rc = cli.cmd_report(SimpleNamespace(level="1", report=None))
    assert rc == 0
