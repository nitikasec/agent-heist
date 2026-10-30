"""Level registry. Each level module defines TITLE, BRIEFING, SYSTEM_PROMPT and an MCP `server`.

Modules are imported lazily so `python -m dvmcp.levels.<level>` can run a level's server cleanly.
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


LEVELS = {
    1: Level(1, "dvmcp.levels.level01_trusting_helpdesk"),
}


def get_level(number: int) -> Level:
    if number not in LEVELS:
        raise KeyError(f"Level {number} does not exist. Available: {sorted(LEVELS)}")
    return LEVELS[number]
