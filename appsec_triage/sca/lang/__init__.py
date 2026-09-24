"""Per-language rules for finding a package's imports and calls in project code.

One module per language (`js`, `php`, `go`), one stop-list per language in
`builtins/`. The project-level functions here walk the files once and apply
the rules of whichever language each file is written in.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .base import Bindings, CallMatch, LanguageRules
from .go import GoRules
from .js import JavaScriptRules
from .php import PhpRules

log = logging.getLogger(__name__)

_RULES: tuple[LanguageRules, ...] = (JavaScriptRules(), PhpRules(), GoRules())
_BY_ECOSYSTEM = {
    "npm": "js", "node": "js", "javascript": "js", "yarn": "js", "js": "js", "ts": "js",
    "composer": "php", "packagist": "php", "php": "php",
    "go": "go", "golang": "go",
}


def rules_for_path(path: str | Path) -> LanguageRules | None:
    suffix = Path(str(path)).suffix.lower()
    return next((r for r in _RULES if suffix in r.suffixes), None)


def rules_for_ecosystem(ecosystem: str) -> LanguageRules | None:
    name = _BY_ECOSYSTEM.get((ecosystem or "").strip().lower())
    return next((r for r in _RULES if r.name == name), None)


@dataclass(slots=True)
class FileScan:
    rel: str
    text: str
    rules: LanguageRules
    bindings: Bindings = field(default_factory=Bindings)


_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", "/index.ts", "/index.js")


# When a project declares no aliases, the two conventions in use: `@/` for the project
# root (some Vue/Nuxt setups) and for `src/` (Vue CLI, most Vite templates). Both are
# tried; a file that exists under neither is left unresolved.
_FALLBACK_ALIASES: dict[str, list[str]] = {"@/": ["", "src"], "~/": ["", "src"]}


def _strip_json_comments(text: str) -> str:
    from .base import blank_comments

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
    return aliases or dict(_FALLBACK_ALIASES)


def _normal(path: str) -> str:
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def _resolve_local(spec: str, importer: str, known: dict[str, FileScan],
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


def bind_project(files: list[FileScan], package: str, *, namespaces: list[str] | None = None,
                 aliases: dict[str, list[str]] | None = None) -> None:
    """Fill each file's bindings, following JS re-exports one module deep.

    A wrapper module (`utils/http.ts` exporting a configured client instance)
    is how most projects use an HTTP client; without this step every call
    through the wrapper would look unbound.
    """
    aliases = aliases or dict(_FALLBACK_ALIASES)
    for scan in files:
        scan.bindings = scan.rules.bindings(scan.text, package, namespaces=namespaces)
    by_rel = {scan.rel: scan for scan in files}
    exported: dict[str, set[str]] = {}
    for scan in files:
        if isinstance(scan.rules, JavaScriptRules) and not scan.bindings.empty:
            names = scan.rules.exports_bound(scan.text, scan.bindings)
            if names:
                exported[scan.rel] = names
    if not exported:
        return
    for scan in files:
        if not isinstance(scan.rules, JavaScriptRules):
            continue
        grew = False
        for spec, original, local in scan.rules.local_imports(scan.text):
            target = _resolve_local(spec, scan.rel, by_rel, aliases)
            if target and original in exported.get(target, ()):
                scan.bindings.receivers.add(local)
                grew = True
        if grew:
            scan.rules._derive(scan.text, scan.bindings)
