"""What a Nuxt application runs without any of its own code importing it: `modules`.

A module listed in `nuxt.config` is loaded by Nuxt itself and may add server
middleware, routes and plugins; the project never imports it. A "not imported /
no call from the project" closure is wrong for such a package. `buildModules`
are left out: they run at build time only.
"""

from __future__ import annotations

import re
from pathlib import Path

_CONFIGS = ("nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs")
_MODULES = re.compile(r"(?<![\w$])modules\s*:\s*\[")
_PACKAGE = re.compile(r"""['"](?P<name>(?:@[\w.\-]+/)?[\w][\w.\-]*)['"]""")


def _array_at(text: str, start: int) -> str:
    """The text of the `[...]` that opens at `start`, brackets balanced."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def framework_invoked(root: Path | str) -> dict[str, str]:
    """package -> `file:line: 'name'` of each module the Nuxt config loads."""
    root = Path(root)
    found: dict[str, str] = {}
    for name in _CONFIGS:
        path = root / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _MODULES.finditer(text):
            if text[max(0, match.start() - 5):match.start()].endswith("build"):
                continue  # buildModules
            body_start = match.end() - 1
            body = _array_at(text, body_start)
            for item in _PACKAGE.finditer(body):
                # `['@nuxtjs/i18n', { locales: ['en'] }]`: strings inside a module's options
                # are not modules.
                if body.count("{", 0, item.start()) != body.count("}", 0, item.start()):
                    continue
                package = item.group("name")
                if package.lower() not in found:
                    offset = body_start + item.start()
                    line = text.count("\n", 0, offset) + 1
                    found[package.lower()] = f"{name}:{line}: '{package}'"
    return found
