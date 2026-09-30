"""Source text read once per run.

The tree does not change while it is triaged, and the checks made for every finding —
is the package imported, does a condition hold, where is it used — each read the
project again: on a large one, minutes of Python per finding, with eight findings at
once on one interpreter. A file's text is kept after the first read, up to a budget.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

_KEPT_FILE = 1 << 20
_BUDGET = int(os.environ.get("APPSEC_SOURCE_CACHE_MB", "512")) << 20

_TEXTS: dict[str, tuple[int, str | None]] = {}
_LOCK = threading.Lock()
_kept = 0


def read(path: Path | str, max_bytes: int) -> str | None:
    """The file's text; None when it is unreadable or larger than `max_bytes`."""
    global _kept
    key = str(path)
    with _LOCK:
        entry = _TEXTS.get(key)
    if entry is None:
        try:
            size = os.stat(key).st_size
        except OSError:
            size = -1
        text = None
        if 0 <= size <= _KEPT_FILE:
            try:
                with open(key, encoding="utf-8", errors="replace") as stream:
                    text = stream.read()
            except OSError:
                size = -1
        entry = (size, text)
        with _LOCK:
            if key not in _TEXTS and _kept + len(text or "") <= _BUDGET:
                _TEXTS[key] = entry
                _kept += len(text or "")
    size, text = entry
    if size < 0 or size > max_bytes:
        return None
    if text is None:
        try:
            with open(key, encoding="utf-8", errors="replace") as stream:
                return stream.read()
        except OSError:
            return None
    return text


def clear() -> None:
    global _kept
    with _LOCK:
        _TEXTS.clear()
        _kept = 0
