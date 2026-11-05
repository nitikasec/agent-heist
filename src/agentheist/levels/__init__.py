"""Level registry. Each level module defines TITLE, BRIEFING, SYSTEM_PROMPT and an MCP `server`.

A level may also set MODE = "victim": the player doesn't chat with the agent, a simulated
victim does, and the module provides SITE_DIR and VICTIM_REQUEST for that flow.

Modules are imported lazily so `python -m agentheist.levels.<level>` can run a level's server cleanly.
"""

import importlib
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class Level:
    number: int
    module_name: str

    @property
    def module(self) -> ModuleType:
        return importlib.import_module(self.module_name)

    @property
    def title(self) -> str:
        return self.module.TITLE

    @property
    def briefing(self) -> str:
        return self.module.BRIEFING

    @property
    def system_prompt(self) -> str:
        return self.module.SYSTEM_PROMPT

    @property
    def mode(self) -> str:
        return getattr(self.module, "MODE", "chat")


LEVELS = {
    1: Level(1, "agentheist.levels.level01_trusting_helpdesk"),
    2: Level(2, "agentheist.levels.level02_poisoned_page"),
    3: Level(3, "agentheist.levels.level03_helpful_integration"),
    4: Level(4, "agentheist.levels.level04_eager_deputy"),
    5: Level(5, "agentheist.levels.level05_poisoned_tool"),
}


def get_level(number: int) -> Level:
    if number not in LEVELS:
        raise KeyError(f"Level {number} does not exist. Available: {sorted(LEVELS)}")
    return LEVELS[number]
