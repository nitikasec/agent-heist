"""Flag checking and local progress tracking.

Flags are stored as SHA-256 hashes so `dvmcp submit` can verify them without
printing the answer.
"""

import hashlib
import json
import re
from pathlib import Path

FLAG_PATTERN = re.compile(r"DVMCP\{[^}\s]+\}")

FLAG_HASHES = {
    1: "169987780150f951a2f2955562de9dd8ef8c79265011f109bf67ec9eb693a7d0",
}

PROGRESS_FILE = Path.home() / ".dvmcp" / "progress.json"


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
