"""What counts as test code — one list, kept in the file every prompt carries."""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath

from .prompts import registry

log = logging.getLogger(__name__)

SECTION = "Test And Non-Production Paths"
_BULLET = re.compile(r"^\s*[-*]\s+`([^`]+)`")

# Compose files describe a developer's machine (`yarn dev --host`, local databases,
# debug ports), never the production deployment: a finding in one is a false
# positive, and a fact read from one proves nothing about production.
LOCAL_ENVIRONMENT_FILES = ("docker-compose*.yml", "docker-compose*.yaml",
                           "compose.yml", "compose.yaml", "compose.*.yml", "compose.*.yaml")


def is_local_environment(path) -> bool:
    name = PurePosixPath(str(path or "").replace("\\", "/")).name.lower()
    return bool(name) and any(fnmatch.fnmatchcase(name, pattern) for pattern in LOCAL_ENVIRONMENT_FILES)


@dataclass(frozen=True, slots=True)
class TestPaths:
    directories: tuple[str, ...] = ()
    files: tuple[str, ...] = ()

    def is_test(self, path) -> bool:
        parts = PurePosixPath(str(path).replace("\\", "/")).parts
        if not parts:
            return False
        if is_local_environment(parts[-1]):
            return True
        if any(part.lower() in self.directories for part in parts[:-1]):
            return True
        return any(fnmatch.fnmatchcase(parts[-1], pattern) for pattern in self.files)


def parse(text: str) -> TestPaths:
    directories: list[str] = []
    files: list[str] = []
    inside = False
    for line in text.splitlines():
        if line.startswith("#"):
            inside = line.lstrip("#").strip() == SECTION
            continue
        match = _BULLET.match(line) if inside else None
        if match is None:
            continue
        pattern = match.group(1).strip()
        if pattern.endswith("/"):
            name = pattern.strip("/").lower()
            if name and "/" not in name:
                directories.append(name)
        elif pattern:
            files.append(pattern)
    return TestPaths(tuple(directories), tuple(files))


@lru_cache(maxsize=1)
def load() -> TestPaths:
    # All parts, not only this run's ecosystems: which files are tests is a fact
    # about the files, whatever the prompts carry.
    paths = parse(registry.all_training_context())
    if not paths.directories and not paths.files:
        log.warning("no test paths listed in %s under %r — nothing is treated as test code",
                    registry.TRAINING_CONTEXT_PATH, SECTION)
    return paths


def is_test(path) -> bool:
    return load().is_test(path)
