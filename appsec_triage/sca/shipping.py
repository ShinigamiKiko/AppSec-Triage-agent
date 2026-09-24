"""Does a vulnerable package reach the running application, and where does it run?

The manifest section is not the answer. On a Vite/webpack front end a package in
`devDependencies` that the source imports is compiled into the bundle; an image
built with `yarn install` and no `--production` carries every development tool;
and a production dependency can pull in a test runner. So the question is asked
of the code and of the Dockerfile, not of the section header:

* runtime     — the application loads it: the source imports it, or a package the
                source imports (or the start command runs) depends on it;
* image_only  — it sits in the runtime image, but nothing that runs loads it;
* build_only  — it exists only while building and testing;
* unknown     — nothing here can tell.

`where` says whether the loading code runs in the browser, in Node, or both (SSR).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..testpaths import is_test

log = logging.getLogger(__name__)

_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "coverage", ".nuxt", ".next",
              "__pycache__", ".venv", "venv", "target"}
_JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
_BUILD_FILE = re.compile(
    r"(^|/)(?:[\w.-]+\.config\.[cm]?[jt]s|\.[\w.-]+rc(?:\.[cm]?[jt]s|\.json)?|gulpfile\.[jt]s|Gruntfile\.[jt]s)$"
    r"|(^|/)(scripts|tools|build|config/webpack|\.storybook|\.husky)/", re.IGNORECASE)
# Server code by convention. The entry file itself is not guessed from its name
# (`src/main.ts` is the browser entry of most SPAs): it is read from the start
# command and package.json, see ProjectShipping._server_entries.
_SERVER_FILE = re.compile(
    r"(^|/)(server|api|backend|functions|middleware|routes|controllers)/|entry-server\.|\.server\.",
    re.IGNORECASE)
_CLIENT_FILE = re.compile(r"entry-client\.|\.client\.|(^|/)public/", re.IGNORECASE)
_SPEC = re.compile(
    r"""(?:\bimport\s+(?:type\s+)?[^;'"`]*?\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)['"`]([^'"`\n]+)['"`]""")
_PROD_FLAGS = re.compile(
    r"--production\b|--prod\b|--omit[= ]dev\b|--only[= ]prod(?:uction)?\b|npm\s+prune\s+--production|"
    r"workspaces\s+focus\b[^\n]*--production|--no-dev\b|NODE_ENV[= ]production", re.IGNORECASE)
_INSTALL = re.compile(r"\b(?:npm\s+(?:ci|install|i)\b|yarn(?:\s+install)?\b(?!\s+(?:build|run|serve|start|dev|lint|test))|"
                      r"pnpm\s+(?:install|i)\b|composer\s+install\b)", re.IGNORECASE)


@dataclass(slots=True)
class ImageFacts:
    """What the runtime stage of the Dockerfile carries."""

    # full: node_modules/vendor with development packages; production: pruned; none: no
    # installed tree in the runtime image; unknown: no Dockerfile or unreadable.
    tree: str = "unknown"
    detail: str = ""
    start_command: str = ""


@dataclass(slots=True)
class ShippingFacts:
    package: str
    shipped: str = "unknown"          # runtime | image_only | build_only | unknown
    where: str = "unknown"            # browser | node | both | unknown
    scope: str = "unknown"            # runtime | dev | unknown  (dependency graph)
    declared: str = ""                # dependencies | devDependencies | transitive | ""
    import_sites: list[str] = field(default_factory=list)
    via: list[str] = field(default_factory=list)     # project requirements that load it
    image: ImageFacts = field(default_factory=ImageFacts)
    detail: str = ""

    def render(self) -> str:
        words = {
            "runtime": "загружается работающим приложением",
            "image_only": "лежит в рабочем образе, но работающий код его не загружает",
            "build_only": "только сборка и тесты — в рабочий образ не попадает",
            "unknown": "поставку определить не удалось",
        }
        where = {"browser": "в браузере (клиентская сборка)", "node": "в Node на сервере",
                 "both": "и в браузере, и в Node (SSR)", "unknown": "среда не определена"}
        lines = [f"поставка: {self.shipped} — {words.get(self.shipped, self.shipped)}"]
        if self.shipped == "runtime":
            lines.append(f"где выполняется: {where.get(self.where, self.where)}")
        if self.declared:
            lines.append(f"объявлен: {self.declared}")
        if self.import_sites:
            lines.append(f"импорт в рабочем коде: {', '.join(self.import_sites[:4])}")
        if self.via:
            lines.append(f"загружается через: {', '.join(self.via[:4])}")
        if self.image.detail:
            lines.append(f"образ: {self.image.detail}")
        if self.detail:
            lines.append(self.detail)
        return "; ".join(lines)


def _dockerfiles(root: Path) -> list[Path]:
    found = []
    for name in ("Dockerfile", "dockerfile", "Containerfile"):
        if (root / name).is_file():
            found.append(root / name)
    for pattern in ("Dockerfile.*", "*.Dockerfile", "docker/Dockerfile*", "deploy/Dockerfile*"):
        found += [p for p in root.glob(pattern) if p.is_file() and p not in found]
    return found


def image_facts(root: Path) -> ImageFacts:
    """Read the last stage of the Dockerfile: does it carry an installed tree, and a pruned one?"""
    files = _dockerfiles(Path(root))
    if not files:
        return ImageFacts("unknown", "Dockerfile не найден")
    path = files[0]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ImageFacts("unknown", f"{path.name} не прочитан: {exc}")
    text = re.sub(r"\\\s*\n", " ", text)
    stages: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.upper().startswith("FROM "):
            alias = re.search(r"\bAS\s+(\S+)", stripped, re.IGNORECASE)
            stages.append(((alias.group(1) if alias else str(len(stages))).lower(), []))
        elif stages:
            stages[-1][1].append(stripped)
    if not stages:
        return ImageFacts("unknown", f"{path.name}: нет ни одной стадии FROM")
    by_name = {name: body for name, body in stages}
    final = stages[-1][1]
    start = next((l for l in reversed(final) if l.upper().startswith(("CMD", "ENTRYPOINT"))), "")

    def installs(body: list[str]) -> tuple[bool, bool]:
        """(installs a tree, prunes development packages)."""
        env_prod = any(l.upper().startswith("ENV") and re.search(r"NODE_ENV[= ]+production", l) for l in body)
        runs = [l for l in body if l.upper().startswith("RUN") and _INSTALL.search(l)]
        if not runs:
            return False, False
        return True, env_prod or all(_PROD_FLAGS.search(l) for l in runs) or any(
            re.search(r"\bnpm\s+prune\b|\byarn\s+workspaces\s+focus\b.*--production", l) for l in body)

    installed, pruned = installs(final)
    if installed:
        tree = "production" if pruned else "full"
        return ImageFacts(tree, f"{path.name}: рабочая стадия сама ставит зависимости"
                          + (" без dev-пакетов" if pruned else " вместе с dev-пакетами"), start)
    copies = [l for l in final if l.upper().startswith("COPY") and re.search(r"node_modules|vendor", l)]
    if copies:
        source = re.search(r"--from=(\S+)", copies[0])
        stage = by_name.get(source.group(1).lower(), []) if source else []
        src_installed, src_pruned = installs(stage)
        if src_installed:
            tree = "production" if src_pruned else "full"
            return ImageFacts(tree, (f"{path.name}: node_modules копируется из стадии {source.group(1) if source else '?'}, "
                                     f"где установка {'без' if src_pruned else 'с'} dev-пакетами"), start)
        return ImageFacts("full", f"{path.name}: рабочая стадия копирует node_modules/vendor целиком", start)
    if any(l.upper().startswith("COPY") and re.search(r"\s\.\s+\S+|\s\./?\s", l) for l in final):
        return ImageFacts("unknown", f"{path.name}: рабочая стадия копирует контекст сборки целиком", start)
    return ImageFacts("none", f"{path.name}: в рабочую стадию установленное дерево не копируется", start)


class ProjectShipping:
    """Facts computed once per project root and reused for every package."""

    def __init__(self, root: Path | str, graph=None) -> None:
        self.root = Path(root)
        self.graph = graph
        self._lock = threading.Lock()
        self._sites: dict[str, list[tuple[str, int]]] | None = None
        self._declared: tuple[set[str], set[str]] | None = None
        self._cache: dict[str, ShippingFacts] = {}
        self.image = image_facts(self.root)
        self.ssr = self._detect_ssr()
        self.bundler = self._detect_bundler()

    # -- project-level facts ---------------------------------------------------------
    def _manifest(self) -> dict:
        try:
            return json.loads((self.root / "package.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return {}

    def _detect_bundler(self) -> str:
        manifest = self._manifest()
        names = {**(manifest.get("dependencies") or {}), **(manifest.get("devDependencies") or {})}
        for bundler in ("vite", "webpack", "rollup", "esbuild", "parcel", "next", "nuxt", "@vue/cli-service",
                        "react-scripts", "@angular/cli"):
            if bundler in names:
                return bundler
        return ""

    def _detect_ssr(self) -> bool:
        """Server-side rendering: the source under src/ runs in Node as well as in the browser.

        A server file alone is not SSR — an express server that hands out a built SPA
        never executes the client code."""
        for pattern in ("**/entry-server.*", "nuxt.config.*", "next.config.*"):
            for path in self.root.glob(pattern):
                if not _SKIP_DIRS.intersection(path.parts) and path.is_file():
                    return True
        for path in self.root.glob("server.*"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"ssrLoadModule|renderToString|createSSRApp|renderToPipeableStream|middlewareMode:\s*['\"]ssr", text):
                return True
        return False

    def declared(self) -> tuple[set[str], set[str]]:
        if self._declared is None:
            from .graph import declared_dependencies

            self._declared = declared_dependencies(self.root) or (set(), set())
        return self._declared

    def _scan(self) -> dict[str, list[tuple[str, int]]]:
        """Every bare import specifier in first-party production code, with its site."""
        with self._lock:
            if self._sites is not None:
                return self._sites
            sites: dict[str, list[tuple[str, int]]] = {}
            count = 0
            for parent, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
                               and not d.lower().startswith("appsec-out")]
                for name in filenames:
                    path = Path(parent) / name
                    if path.suffix.lower() not in _JS_SUFFIXES:
                        continue
                    rel = path.relative_to(self.root).as_posix()
                    if is_test(rel) or _BUILD_FILE.search(rel):
                        continue
                    try:
                        if path.stat().st_size > 600_000:
                            continue
                        text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    count += 1
                    for match in _SPEC.finditer(text):
                        spec = match.group(1)
                        if spec.startswith((".", "/", "@/", "~/", "#")):
                            continue
                        package = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                        sites.setdefault(package.lower(), []).append((rel, text.count("\n", 0, match.start()) + 1))
            log.info("shipping: %d production source file(s), %d package(s) imported", count, len(sites))
            self._sites = sites
            return sites

    def _start_bins(self) -> set[str]:
        """Packages whose executables the image's start command runs (`yarn serve` -> `ts-node`)."""
        command = self.image.start_command
        if not command:
            return set()
        scripts = self._manifest().get("scripts") or {}
        words = re.findall(r"[\w:.@/-]+", command)
        text = command
        for index, word in enumerate(words):
            if word in ("npm", "yarn", "pnpm") and index + 1 < len(words):
                script = words[index + 2] if words[index + 1] == "run" and index + 2 < len(words) else words[index + 1]
                text += " " + str(scripts.get(script, ""))
        prod, dev = self.declared()
        return {token for token in re.findall(r"[\w@/.-]+", text) if token.lower() in prod | dev}

    def _server_entries(self) -> set[str]:
        """Files Node starts: `main` of package.json and the files the start scripts run."""
        manifest = self._manifest()
        entries: set[str] = set()
        if isinstance(manifest.get("main"), str):
            entries.add(manifest["main"])
        scripts = manifest.get("scripts") or {}
        commands = [str(scripts.get(k, "")) for k in ("start", "serve", "server", "prod", "dev")]
        commands.append(self.image.start_command)
        for command in commands:
            for token in re.findall(r"(?:node|ts-node|tsx|nodemon|bun|deno\s+run)\s+(?:--?[\w-]+(?:=\S+)?\s+)*([\w./-]+)",
                                    command):
                entries.add(token)
        out: set[str] = set()
        for entry in entries:
            entry = entry.lstrip("./")
            for candidate in (entry, *(entry + ext for ext in (".ts", ".js", ".mjs", ".cjs"))):
                if (self.root / candidate).is_file():
                    out.add(candidate)
        return out

    def _where(self, files: list[str]) -> str:
        server = client = shared = False
        entries = getattr(self, "_entries", None)
        if entries is None:
            entries = self._entries = self._server_entries()
        for rel in files:
            if rel in entries or _SERVER_FILE.search(rel) or (not self.bundler and not _CLIENT_FILE.search(rel)):
                server = True
            elif _CLIENT_FILE.search(rel):
                client = True
            else:
                shared = True
        if shared:
            if self.ssr:
                return "both"
            if self.bundler:
                client = True
            else:
                server = True
        if server and client:
            return "both"
        return "node" if server else "browser" if client else "unknown"

    # -- per package ------------------------------------------------------------------
    def facts(self, package: str, ecosystem: str = "npm") -> ShippingFacts:
        key = (package or "").lower()
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        facts = self._compute(key, (ecosystem or "").lower())
        with self._lock:
            self._cache[key] = facts
        return facts

    def _compute(self, package: str, ecosystem: str) -> ShippingFacts:
        facts = ShippingFacts(package, image=self.image)
        prod, dev = self.declared()
        facts.declared = ("dependencies" if package in prod else "devDependencies" if package in dev
                          else "transitive" if (prod or dev) else "")
        facts.scope = self.graph.scope(package) if self.graph is not None else (
            "runtime" if package in prod else "dev" if package in dev else "unknown")
        if ecosystem not in ("npm", "node", "javascript", "yarn", ""):
            # No bundling outside JS: the section and the image decide.
            return self._by_scope(facts)

        sites = self._scan()
        own = sites.get(package, [])
        if own:
            facts.shipped = "runtime"
            facts.import_sites = [f"{f}:{l}" for f, l in own[:6]]
            facts.where = self._where([f for f, _ in own])
            if facts.declared == "devDependencies":
                facts.detail = (f"{package} объявлен в devDependencies, но импортируется рабочим кодом — "
                                + ("бандлер вшивает его в сборку" if self.bundler else "в рантайме он нужен"))
            return facts

        roots = set(self.graph.roots_of(package)) if self.graph is not None else set()
        loaded = sorted(r for r in roots if r in sites)
        started = sorted(r for r in roots if r in self._start_bins())
        if loaded or started:
            facts.shipped = "runtime"
            facts.via = loaded + [s for s in started if s not in loaded]
            files = [f for r in loaded for f, _ in sites[r]]
            facts.where = self._where(files) if files else "node"
            if started:
                facts.where = "both" if facts.where == "browser" else ("node" if facts.where == "unknown" else facts.where)
            return facts
        if roots or facts.scope != "unknown":
            facts.via = []
            facts.detail = ("ни рабочий код, ни команда запуска не загружают ни его, ни пакеты, "
                            f"которые его тянут ({', '.join(sorted(roots)[:4]) or 'не определены'})")
            if self.image.tree == "full":
                facts.shipped = "image_only"
            elif self.image.tree == "production":
                facts.shipped = "build_only" if facts.scope != "runtime" else "image_only"
            elif self.image.tree == "none":
                facts.shipped = "build_only"
            else:
                facts.shipped = "build_only" if facts.scope == "dev" else "unknown"
            return facts
        return facts

    def _by_scope(self, facts: ShippingFacts) -> ShippingFacts:
        if facts.scope == "runtime" or facts.declared == "dependencies":
            facts.shipped, facts.where = "runtime", "node"
        elif facts.scope == "dev" or facts.declared == "devDependencies":
            facts.shipped = "image_only" if self.image.tree == "full" else "build_only"
        return facts
