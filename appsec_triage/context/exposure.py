"""Who can reach a file: Symfony's access_control applied to the routes that lead to it.

A finding behind a login waits behind one anyone on the internet can trigger; it is
not closed by that. So this orders the queue and nothing else, and it says
"authenticated" only when every route found for the file falls under a rule that
requires a role — a file with no route found, or with one public route, says nothing.

Routes come from the controller's own `#[Route]` / `@Route` (class prefix included),
from `config/routes*.yaml` prefixes of the directory it lives in, from the EasyAdmin
dashboard for CRUD controllers, and, for a template, from the controllers that render
it. Laravel is not read yet.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_PUBLIC_ROLES = {"PUBLIC_ACCESS", "IS_AUTHENTICATED_ANONYMOUSLY"}
_RULE = re.compile(r"^\s*-\s*\{\s*path:\s*(?P<path>[^,}]+?)\s*,\s*roles:\s*(?P<roles>\[[^\]]*\]|[^,}]+?)\s*(?:,|\})",
                   re.MULTILINE)
_ROUTE = re.compile(r"""(?:#\[Route\(|@Route\()\s*(?:path\s*[:=]\s*)?['"](?P<path>[^'"]*)['"]""")
_CLASS = re.compile(r"^\s*(?:final\s+|abstract\s+)*class\s+\w+(?:\s+extends\s+(?P<parent>[\w\\]+))?", re.MULTILINE)
_SKIP = {".git", "vendor", "node_modules", "var", "tests", "test", "public"}
_MAX_FILES = 4000


@dataclass(slots=True)
class Rule:
    pattern: str
    roles: list[str]
    line: int

    @property
    def public(self) -> bool:
        return not self.roles or all(r in _PUBLIC_ROLES for r in self.roles)


@dataclass(slots=True)
class Exposure:
    root: Path
    rules: list[Rule]
    source: str
    open_firewalls: list[str] = field(default_factory=list)
    _php: dict[str, str] = field(default_factory=dict)
    _prefixes: list[tuple[str, str]] = field(default_factory=list)
    _dashboards: list[str] = field(default_factory=list)

    def of(self, file_path: str) -> str:
        """"authenticated: …" or "" (public, or not established)."""
        rel = self._relative(file_path)
        if rel is None:
            return ""
        routes = self._routes_of(rel)
        if not routes:
            return ""
        roles: set[str] = set()
        lines: set[int] = set()
        for route in routes:
            if any(re.search(pattern, route) for pattern in self.open_firewalls):
                return ""  # a firewall with `security: false`: no access control at all
            rule = next((r for r in self.rules if re.search(r.pattern, route)), None)
            if rule is None or rule.public:
                return ""
            roles.update(rule.roles)
            lines.add(rule.line)
        where = ", ".join(f"{self.source}:{n}" for n in sorted(lines))
        shown = ", ".join(sorted(routes)[:3]) + (f" и ещё {len(routes) - 3}" if len(routes) > 3 else "")
        return f"authenticated: {', '.join(sorted(roles))} — маршруты {shown} ({where})"

    # -- routes ---------------------------------------------------------------------------
    def _relative(self, file_path: str) -> str | None:
        path = (file_path or "").replace("\\", "/")
        for marker in ("/src/", "/templates/"):
            if marker in path and not path.startswith(("src/", "templates/")):
                path = path[path.index(marker) + 1:]
        return path if path.startswith(("src/", "templates/")) else None

    def _routes_of(self, rel: str) -> set[str]:
        if rel.endswith(".php"):
            return self._controller_routes(rel)
        if rel.startswith("templates/"):
            name = rel[len("templates/"):]
            if name.startswith("bundles/EasyAdminBundle/"):
                return set(self._dashboards)
            renderers = [p for p, text in self._php.items() if name in text]
            routes: set[str] = set()
            for path in renderers:
                found = self._controller_routes(path)
                if not found:
                    return set()  # a renderer with no known route: the template's reach is unknown
                routes |= found
            return routes
        return set()

    def _controller_routes(self, rel: str) -> set[str]:
        text = self._php.get(rel, "")
        if not text:
            return set()
        head = _CLASS.search(text)
        class_at = head.start() if head else 0
        prefix = next((m.group("path") for m in _ROUTE.finditer(text[:class_at])), "")
        dir_prefix = next((p for d, p in self._prefixes if rel == d or (d.endswith("/") and rel.startswith(d))), "")
        own = [m.group("path") for m in _ROUTE.finditer(text[class_at:])]
        routes = {self._join(dir_prefix, prefix, r) for r in own}
        if not routes and self._extends_crud(text):
            routes = set(self._dashboards)  # EasyAdmin serves CRUD actions under the dashboard's route
        return routes

    def _extends_crud(self, text: str, depth: int = 0) -> bool:
        """An EasyAdmin CRUD controller, directly or through the project's own base classes."""
        head = _CLASS.search(text)
        parent = head.group("parent").split("\\")[-1] if head and head.group("parent") else ""
        if not parent or depth > 3:
            return False
        if parent == "AbstractCrudController":
            return True
        base = next((t for t in self._php.values() if re.search(rf"\bclass\s+{re.escape(parent)}\b", t)), "")
        return bool(base) and self._extends_crud(base, depth + 1)

    @staticmethod
    def _join(*parts: str) -> str:
        path = "/" + "/".join(p.strip("/") for p in parts if p and p.strip("/"))
        return re.sub(r"\{[^}]+\}", "x", path)


def read(roots) -> Exposure | None:
    """The access rules and routes of a Symfony application, or None when there are none."""
    for root in roots or []:
        root = Path(root)
        security = root / "config" / "packages" / "security.yaml"
        if not security.is_file():
            continue
        text = security.read_text(encoding="utf-8", errors="replace")
        start = text.find("access_control:")
        if start < 0:
            continue
        rules = []
        for m in _RULE.finditer(text, start):
            raw = m.group("roles").strip().strip("[]")
            roles = [r.strip().strip("'\"") for r in raw.split(",") if r.strip()]
            pattern = m.group("path").strip().strip("'\"")
            try:
                re.compile(pattern)
            except re.error:
                continue
            rules.append(Rule(pattern, roles, text.count("\n", 0, m.start()) + 1))
        if not rules:
            continue
        exposure = Exposure(root, rules, security.relative_to(root).as_posix(),
                            open_firewalls=[p for p in _open_firewalls(text) if _compiles(p)])
        exposure._php = _php_sources(root)
        exposure._prefixes = _route_prefixes(root)
        exposure._dashboards = sorted({
            route for rel, t in exposure._php.items() if "AbstractDashboardController" in t
            for route in exposure._controller_routes(rel)})
        log.info("access control: %d rule(s), %d dashboard route(s) from %s",
                 len(rules), len(exposure._dashboards), exposure.source)
        return exposure
    return None


def _compiles(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _php_sources(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    src = root / "src"
    for parent, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in _SKIP]
        for name in filenames:
            if name.endswith(".php") and len(out) < _MAX_FILES:
                path = Path(parent) / name
                try:
                    out[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
    return out


def _route_prefixes(root: Path) -> list[tuple[str, str]]:
    """(source directory, prefix) from route imports in config/routes*.yaml, longest first."""
    files = [root / "config" / "routes.yaml", *sorted((root / "config" / "routes").glob("*.yaml"))]
    out = []
    for path in files:
        if not path.is_file():
            continue
        import yaml

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        for entry in data.values() if isinstance(data, dict) else []:
            if not isinstance(entry, dict) or not entry.get("prefix") or not isinstance(entry.get("resource"), str):
                continue
            resource = entry["resource"].replace("\\", "/")
            if "../src/" in resource or resource.startswith("src/"):
                target = "src/" + resource.split("src/", 1)[1].split("{")[0]
                # A file is imported as itself; a directory covers what lies under it.
                target = target if target.endswith(".php") else target.rstrip("/") + "/"
                prefix = entry["prefix"] if isinstance(entry["prefix"], str) else ""
                if prefix:
                    out.append((target, prefix))
    return sorted(out, key=lambda item: (not item[0].endswith(".php"), -len(item[0])))


def _open_firewalls(text: str) -> list[str]:
    """Patterns of firewalls with `security: false`: access_control does not apply under them."""
    import yaml

    try:
        firewalls = ((yaml.safe_load(text) or {}).get("security") or {}).get("firewalls") or {}
        return [str(f["pattern"]) for f in firewalls.values()
                if isinstance(f, dict) and f.get("pattern") and f.get("security") is False]
    except (yaml.YAMLError, AttributeError):
        pass
    out = []  # a regex in a flow mapping can break YAML: read the blocks line by line
    for block in re.finditer(r"^(\s+)[\w-]+:\s*\n((?:\1\s+.*\n?)+)", text, re.MULTILINE):
        body = block.group(2)
        pattern = re.search(r"^\s*pattern:\s*['\"]?([^'\"\n]+)", body, re.MULTILINE)
        if pattern and re.search(r"^\s*security:\s*false\b", body, re.MULTILINE):
            out.append(pattern.group(1).strip())
    return out
