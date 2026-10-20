"""Where things live in this project — so a search starts where the answer usually is.

A stack profile names the roles a framework gives its directories — routes, access
control, input binding, persistence, templates — as path patterns. This module walks
the project once, keeps the patterns that match something that exists, and renders a
few lines for the code walk.

Measured before it existed: on a Symfony service 40 of 129 open questions were about
configuration (`security.yaml`, API Platform resources) the model had to go looking
for, and on a Go demo the search step spent its calls on a path that did not exist
(`src/parser.go` for `parser.go`) and on a dependency's internals.

It is a starting point, never a boundary. A search that finds nothing in a listed
place says nothing about the rest of the project, and the rendered text says so —
"auth lives in src/Security/, nothing there, so there is no auth" is the failure a
map like this invites, and for a security tool it is the worst one.

Patterns are matched against what is on disk, not assumed: an Express project keeps
its routes in `lib/routes/` as often as in `src/routes/`, and a Nuxt project may move
everything under `src/`. Only paths that exist are shown, relative to the project
root, so they can be passed to read_file and search_code exactly as written.

Two measured ways a map points the wrong way, both on a repository that is a Vue
frontend with an Express server in one tree: a generic `*/auth/` pattern took the
Vuex store module `src/store/modules/auth/` for server middleware, and `passport*`
took two images for Passport.js. So a file is shown only when it is code or
configuration the evidence tools would read, and a profile can exclude the parts of
a tree that belong to another stack (`where_exclude`).
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import _EXCLUDED, _EXTENSIONS, _SPECIAL_FILES

log = logging.getLogger(__name__)

# Build output and caches are not the project's code; the evidence tools skip
# _EXCLUDED, and the map must not point where they will not read. Tests are code,
# but not where a request comes in: `tests/components/` is not the app's components.
# Hidden directories (`.git`, `.nuxt`, a CodeQL database) and this agent's own
# output (`appsec-out*`) are skipped by prefix in `_walk`.
_SKIP = {name.lower() for name in _EXCLUDED} | {
    "var", "cache", "dist", "build", "coverage", "tests", "test", "__tests__", "e2e", "cypress",
    "testdata",
}
_MAX_ENTRIES = 50_000
_MAX_DEPTH = 6
# Shown in the order the profile lists its patterns: the author puts what matters first.
# Sorted by depth instead, `config/auth.php` and three other configs pushed Laravel's
# `app/Http/Middleware/` — where the authentication is — off the line.
_PATHS_PER_ROLE = 5
# A directory this small is shown as its files. Shown as `config/routes/ (6 files)`, the
# model asked for `config/routes/admin.yaml`, which does not exist: it has no way to list
# a directory, so it guessed.
_LIST_FILES = 6


@dataclass(slots=True)
class _Tree:
    """Every directory (with the files under it) and every file, relative to the root."""

    files: set[str] = field(default_factory=set)
    dirs: dict[str, int] = field(default_factory=dict)
    truncated: bool = False


def _walk(root: Path) -> _Tree:
    tree = _Tree()
    entries = 0
    for current, dirnames, filenames in os.walk(root):
        rel = Path(current).relative_to(root).as_posix()
        rel = "" if rel == "." else rel
        depth = 0 if not rel else rel.count("/") + 1
        dirnames[:] = sorted(d for d in dirnames
                             if d.lower() not in _SKIP and not d.startswith(".")
                             and not d.lower().startswith("appsec-out")
                             and not os.path.islink(os.path.join(current, d)) and depth < _MAX_DEPTH)
        for name in filenames:
            entries += 1
            if entries > _MAX_ENTRIES:
                tree.truncated = True
                return tree
            path = f"{rel}/{name}" if rel else name
            tree.files.add(path)
            # Count the file for every directory above it, so `src/Controller/` reports its whole subtree.
            parts = rel.split("/") if rel else []
            for i in range(1, len(parts) + 1):
                key = "/".join(parts[:i])
                tree.dirs[key] = tree.dirs.get(key, 0) + 1
        if rel and rel not in tree.dirs:
            tree.dirs[rel] = 0
    return tree


def _readable(path: str) -> bool:
    """Code or configuration the evidence tools read — not an image that happens to match a name."""
    name = path.rsplit("/", 1)[-1]
    if name.startswith("."):        # `.gitignore`, macOS `._index.ts` copies: not the project's code
        return False
    suffix = os.path.splitext(name)[1].lower()
    return suffix in _EXTENSIONS or name.lower() in _SPECIAL_FILES or suffix == ""


def _excluded(path: str, exclude: tuple[str, ...]) -> bool:
    bare = path.rstrip("/")
    return any(fnmatch.fnmatchcase(bare, ex) or fnmatch.fnmatchcase(bare, ex.rstrip("/") + "/*")
               for ex in exclude)


def _matches(tree: _Tree, patterns: tuple[str, ...],
             exclude: tuple[str, ...] = ()) -> list[tuple[str, int | None]]:
    """(path, files under it or None for a file) for every pattern that hits something on disk.

    A pattern ending in `/` names a directory; anything else may be a file or a
    directory. `*` crosses `/`, so `*/routes/` finds `lib/routes` and `src/api/routes`.
    Case-sensitive on every platform: `src/Controller` is not `src/controller`.
    """
    found: dict[str, int | None] = {}
    order: dict[str, int] = {}
    for index, pattern in enumerate(patterns):
        wants_dir = pattern.endswith("/")
        glob = pattern.rstrip("/")
        for path, count in tree.dirs.items():
            if fnmatch.fnmatchcase(path, glob):
                found[path + "/"] = count
                order.setdefault(path + "/", index)
        if not wants_dir:
            for path in tree.files:
                if fnmatch.fnmatchcase(path, glob) and _readable(path):
                    found[path] = None
                    order.setdefault(path, index)
    found = {p: c for p, c in found.items() if not _excluded(p, exclude)}
    # A directory inside another one already listed adds nothing: keep the outer.
    keep = {p: c for p, c in found.items()
            if not any(other != p and other.endswith("/") and p.startswith(other) for other in found)}
    return sorted(keep.items(), key=lambda item: (order[item[0]], item[0].count("/"), -(item[1] or 0), item[0]))


def _describe(tree: _Tree, path: str, count: int | None, prefix: str = "",
              exclude: tuple[str, ...] = ()) -> str:
    if count is None:
        return prefix + path
    if count <= _LIST_FILES:
        inside = sorted(f for f in tree.files
                        if f.startswith(path) and _readable(f) and not _excluded(f, exclude))
        if inside:
            return ", ".join(prefix + f for f in inside)
    return f"{prefix}{path} ({count} file{'s' if count != 1 else ''})"


def render(profiles, roots: list[Path]) -> str:
    """The "where things live" section for these stacks in these roots, or "" when nothing matched."""
    roots = [Path(r) for r in roots if Path(r).is_dir()]
    profiles = [p for p in profiles if getattr(p, "where", None)]
    if not roots or not profiles:
        return ""
    trees = {root: _walk(root) for root in roots}
    lines: list[str] = []
    # A path once across profiles. Two profiles can apply to one tree — Fiber and Go both
    # match a Fiber service — and the second would list the same handlers and middleware
    # again. Within a profile each role keeps its own paths: `auth and middleware` must not
    # vanish because its directory also sits under `internal/http/`.
    seen: set[str] = set()
    for profile in profiles:
        exclude = tuple(getattr(profile, "exclude", ()) or ())
        rows: list[str] = []
        shown_here: set[str] = set()
        for role, patterns in profile.where:
            found: list[tuple[str, str]] = []
            for root, tree in trees.items():
                prefix = "" if len(trees) == 1 else f"{root.name}/"
                for path, count in _matches(tree, patterns, exclude):
                    key = prefix + path
                    if key in seen or any(s.endswith("/") and key.startswith(s) for s in seen):
                        continue
                    found.append((key, _describe(tree, path, count, prefix, exclude)))
            shown_here.update(key for key, _ in found[:_PATHS_PER_ROLE])
            hits = [text for _, text in found]
            if hits:
                shown = ", ".join(hits[:_PATHS_PER_ROLE])
                more = f" (+{len(hits) - _PATHS_PER_ROLE} more)" if len(hits) > _PATHS_PER_ROLE else ""
                rows.append(f"- {role}: {shown}{more}")
        seen |= shown_here
        if rows:
            lines += [f"Detected: {profile.name}.", *rows]
    if not lines:
        return ""
    if any(tree.truncated for tree in trees.values()):
        lines.append(f"(The project has more than {_MAX_ENTRIES} files; the map covers the part walked.)")
    return "\n".join([
        "## Where things live in this project",
        "Paths that exist, relative to the project root — pass them to read_file and search_code as "
        "written. Start your search here. A search that finds nothing in these places is NOT evidence "
        "that something is absent: search the rest of the project before concluding it is missing.",
        *lines,
    ])
