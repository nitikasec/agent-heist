"""Flag checking and local progress tracking.

Flags are stored as SHA-256 hashes so `agentheist submit` can verify them without
printing the answer.
"""

import hashlib
import json
import re
from pathlib import Path

FLAG_PATTERN = re.compile(r"HEIST\{[^}\s]+\}")

FLAG_HASHES = {
    1: "9107d5b48eddcd55c9bc11a03f6f49ed37b7b96359d252a47625b2a0815613fe",
    2: "bfb42bc83886bd31ebe4dbd5a55b6f967172f0c7ec7c7354de8a8ed44d27c6ea",
}

PROGRESS_FILE = Path.home() / ".agentheist" / "progress.json"


def check_flag(level: int, flag: str) -> bool:
    expected = FLAG_HASHES.get(level)
    return expected is not None and hashlib.sha256(flag.strip().encode()).hexdigest() == expected


def find_flags(text: str) -> list[str]:
    return FLAG_PATTERN.findall(text)


def load_progress(path: Path = PROGRESS_FILE) -> set[int]:
    try:
        return set(json.loads(path.read_text())["solved"])
    except (FileNotFoundError, KeyError, ValueError):
        return set()


def mark_solved(level: int, path: Path = PROGRESS_FILE) -> None:
    solved = load_progress(path) | {level}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"solved": sorted(solved)}))
