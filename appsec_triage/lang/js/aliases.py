"""Import aliases a JS/TS project declares (`@/utils/http`), and the file each import names."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..base import blank_comments

_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", "/index.ts", "/index.js")


# When a project declares no aliases, the two conventions in use: `@/` for the project
# root (some Vue/Nuxt setups) and for `src/` (Vue CLI, most Vite templates). Both are
# tried; a file that exists under neither is left unresolved.
FALLBACK_ALIASES: dict[str, list[str]] = {"@/": ["", "src"], "~/": ["", "src"]}


def _strip_json_comments(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", blank_comments(text, line_comments=("//",), backtick_strings=False))


def project_aliases(root: Path) -> dict[str, list[str]]:
    """Import aliases as the project itself declares them.

    Read from `compilerOptions.paths` (+ `baseUrl`) of tsconfig/jsconfig and from
    `resolve.alias` in a Vite/webpack config when it is a plain `'@': resolve(__dirname, 'src')`.
    Nothing is assumed about one particular repository; without a declaration the
    common conventions are tried.
    """
    root = Path(root)
    aliases: dict[str, list[str]] = {}
    for name in ("tsconfig.json", "jsconfig.json", "tsconfig.base.json", "tsconfig.app.json"):
        path = root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(_strip_json_comments(path.read_text(encoding="utf-8", errors="replace")))
        except ValueError:
            continue
        options = (data or {}).get("compilerOptions") or {}
        base = str(options.get("baseUrl") or ".")
        for pattern, targets in (options.get("paths") or {}).items():
            if not pattern.endswith("/*"):
                continue
            prefix = pattern[:-1]
            for target in targets or []:
                if target.endswith("/*"):
                    rel = (Path(base) / target[:-2]).as_posix()
                    aliases.setdefault(prefix, []).append(_normal(rel))
    for name in ("vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs",
                 "webpack.config.js", "vue.config.js"):
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(
                r"""['"]?([@~$#][\w-]*)['"]?\s*:\s*(?:path\.)?resolve\(\s*__dirname\s*,\s*['"]([^'"]*)['"]""", text):
            aliases.setdefault(match.group(1).rstrip("/") + "/", []).append(_normal(match.group(2)))
        for match in re.finditer(
                r"""['"]?([@~$#][\w-]*)['"]?\s*:\s*fileURLToPath\(\s*new URL\(\s*['"]([^'"]*)['"]""", text):
            aliases.setdefault(match.group(1).rstrip("/") + "/", []).append(_normal(match.group(2)))
    return aliases or dict(FALLBACK_ALIASES)


def _normal(path: str) -> str:
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def resolve_local(spec: str, importer: str, known: dict[str, object],
                   aliases: dict[str, list[str]]) -> str | None:
    """A project-relative import (`./api`, `@/utils/http`) to the file it names."""
    bases: list[str] = []
    for prefix, targets in sorted(aliases.items(), key=lambda item: -len(item[0])):
        if spec.startswith(prefix):
            bases = [_normal(f"{target}/{spec[len(prefix):]}") for target in targets]
            break
    if not bases:
        if not spec.startswith("."):
            return None
        bases = [_normal((Path(importer).parent / spec).as_posix())]
    for base in bases:
        for candidate in (base, *(base + ext for ext in _JS_EXTENSIONS)):
            if candidate in known:
                return candidate
    return None
