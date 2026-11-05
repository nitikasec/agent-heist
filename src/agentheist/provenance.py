"""Reproducibility metadata for a scoreboard run: what was tested, with what, and when.

A benchmark number is only worth citing if someone else can reproduce it. This records the
provider, model ids, run count, timestamp and tool version, the exact command to re-run, and -
honestly - the one source of variation the lab cannot pin: the model itself is nondeterministic,
so a single cell is weaker evidence than a success rate over several runs.
"""

import datetime
import os
import platform
import subprocess
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

from agentheist.backends import DEFAULT_LOCAL_URL, provider


def _agentheist_version() -> str:
    try:
        return version("agentheist")
    except PackageNotFoundError:
        return "unknown"


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3, cwd=os.path.dirname(__file__),
        )
        return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None
    except Exception:
        return None


def _base_url() -> str:
    if provider() == "openai":
        return os.environ.get("AGENTHEIST_BASE_URL", DEFAULT_LOCAL_URL)
    return os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Provenance:
    generated_at: str
    agentheist_version: str
    python_version: str
    provider: str
    base_url: str
    git_commit: str | None
    models: list[str]
    runs: int
    levels: list[int]
    command: str

    def to_markdown(self) -> list[str]:
        commit = self.git_commit or "unknown"
        return [
            "## Run provenance",
            "",
            f"- **Generated:** {self.generated_at}",
            f"- **agentheist:** {self.agentheist_version} (commit `{commit}`)",
            f"- **Python:** {self.python_version}",
            f"- **Provider:** {self.provider} ({self.base_url})",
            f"- **Models:** {', '.join(f'`{m}`' for m in self.models)}",
            f"- **Levels:** {', '.join(str(n) for n in self.levels)}",
            f"- **Runs per cell:** {self.runs}",
            "",
            "Reproduce with:",
            "",
            "```",
            self.command,
            "```",
            "",
            "> Models are nondeterministic: the attacker and the servers are fixed, but a model may "
            "answer differently between runs. Trust a success rate over several `--runs`, not a single cell.",
        ]


def collect(models: list[str], runs: int, levels: list[int], command: str) -> Provenance:
    return Provenance(
        generated_at=_now(),
        agentheist_version=_agentheist_version(),
        python_version=platform.python_version(),
        provider=provider(),
        base_url=_base_url(),
        git_commit=_git_commit(),
        models=models,
        runs=runs,
        levels=levels,
        command=command,
    )


def reproduce_command(level: str, models: str | None, runs: int, compare: bool) -> str:
    """The canonical command that reproduces this scoreboard run."""
    parts = ["agentheist", "bench", str(level)]
    if models:
        parts += ["--models", models]
    if runs and runs != 1:
        parts += ["--runs", str(runs)]
    if compare:
        parts.append("--compare")
    parts += ["--report", "board.md"]
    return " ".join(parts)
