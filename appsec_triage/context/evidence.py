"""Bounded, static repository evidence. No config evaluation or shared caches."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from ..redact import redact_secrets
from .source import SourceResolver

MAX_FILES = 500
MAX_ENTRIES = 4000
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 2_000_000
MAX_LOCATIONS = 48
_EXTENSIONS = frozenset({
    ".php", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java", ".kt", ".kts",
    ".cs", ".c", ".h", ".cpp", ".hpp", ".cc", ".rs", ".swift", ".scala", ".vue", ".svelte", ".twig", ".sh",
    ".yaml", ".yml", ".xml", ".json",
})
_SPECIAL_FILES = frozenset({
    "dockerfile", "dockerfile.prod", "dockerfile.dev", "go.mod", "go.sum",
    ".gitlab-ci.yml", "deployment.yaml", "deployment.yml", "values.yaml",
})
_EXCLUDED = frozenset({
    ".git", ".svn", ".hg", "vendor", "node_modules", ".ssh", ".aws", ".gnupg", "secrets", "keys",
    "__pycache__", ".venv", "venv",
})
_CODE_EXTENSIONS = _EXTENSIONS - {".yaml", ".yml", ".xml", ".json"}
_SECRET_NAME = r"(?:[\w.-]+[_.-])?(?:passwords?|secrets?|tokens?|api_keys?|private_keys?)"
_SECRET_HEAD = re.compile(
    rf'''(?<![\w.-])["']?{_SECRET_NAME}["']?[ \t]*(?:=>|:=|:|=)[ \t]*''', re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    rf'''(?P<head>{_SECRET_HEAD.pattern})(?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^ \t\n\r,;}}\]{{\[<>#][^\n\r,;}}\]<>]*)''',
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(r"%env\([^\r\n]*?\)%|\$\{[^\r\n}]+\}")
_STATIC_NOTE = (
    "Repository evidence is static, not effective runtime configuration. File order is preserved; "
    "environment overrides are labeled, not merged. Imports are text only, never executed. "
    "Absent evidence is not proof a feature is disabled; bounded scans may omit files."
)


def _redact(text: str) -> str:
    placeholders = []

    def protect(match):
        placeholders.append(match.group())
        return f"~P{len(placeholders) - 1}~"

    text = _PLACEHOLDER.sub(protect, text)
    # Class/service references are configuration, including for the entropy pass.
    text = re.sub(r'''[\\A-Za-z_]\w*(?:\\+\w+)+(?:\:\:class)?|\b\w+::class\b''', protect, text)

    def hide(value):
        if re.fullmatch(r'''["']?~P\d+~["']?''', value.strip()):
            return value
        if value.strip().lower() in {"true", "false", "yes", "no", "on", "off", "null", "~"}:
            return value
        # Keep line numbers valid even for multi-line literals.
        return "<REDACTED>" + "\n" * value.count("\n")

    # Hide balanced flow collections in full, not just their first scalar.
    spans = []
    for match in _SECRET_HEAD.finditer(text):
        start = match.end()
        if start >= len(text) or text[start] not in "[{":
            continue
        key = re.split(r"[ \t]*(?:=>|:=|:|=)", match.group(), maxsplit=1)[0].strip("\"'")
        if text[start] == "{" and key.lower() == "access_token" and re.match(
            r'''\{[ \t]*["']?token_handler["']?[ \t]*:''', text[start:]
        ):
            continue
        stack, quote = [], None
        escaped = False
        for end in range(start, len(text)):
            char = text[end]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char in "[{":
                stack.append(char)
            elif char in "]}":
                stack.pop()
                if not stack:
                    break
        spans.append((start, end + 1))
    for start, end in reversed(spans):
        if not any(lo < start < hi for lo, hi in spans):
            text = text[:start] + hide(text[start:end]) + text[end:]

    # YAML credential collections and block scalars retain their original lines.
    lines = text.splitlines(keepends=True)
    secret_indent = None
    for i, line in enumerate(lines):
        indent = len(line) - len(line.lstrip())
        if secret_indent is not None:
            if (not line.strip() or indent > secret_indent or
                    (indent == secret_indent and line.lstrip().startswith("- "))):
                lines[i] = " " * indent + "<REDACTED>" + ("\n" if line.endswith("\n") else "")
                continue
            secret_indent = None
        match = re.match(rf'''[ \t]*(?:-[ \t]+)?["']?(?P<key>{_SECRET_NAME})["']?[ \t]*:[ \t]*(?P<value>[^\r\n]*)''', line, re.IGNORECASE)
        if match:
            value = match["value"].strip()
            following = next((s for s in lines[i + 1:] if s.strip()), "")
            if (value.startswith(("|", ">")) or
                    (not value.split("#", 1)[0].strip() and
                      not (match["key"].lower() == "access_token" and
                           re.match(r'''[ \t]*["']?token_handler["']?[ \t]*:''', following)))):
                secret_indent = indent
    text = _ASSIGNMENT.sub(lambda m: m["head"] + hide(m["value"]), "".join(lines))
    text = re.sub(
        rf"(<(?P<name>{_SECRET_NAME})\b[^>]*>)([^<]*)(</(?P=name)\s*>)",
        lambda m: m[1] + hide(m[3]) + m[4], text, flags=re.IGNORECASE,
    )
    text = re.sub(
        rf'''(<(?:parameter|argument|item)\b[^>]*\b(?:key|name)\s*=\s*["']{_SECRET_NAME}["'][^>]*>)([^<]*)(</[^>]+>)''',
        lambda m: m[1] + hide(m[2]) + m[3], text, flags=re.IGNORECASE,
    )

    def xml_attributes(match):
        tag = match.group()
        if re.search(rf'''\b(?:key|name)\s*=\s*["']{_SECRET_NAME}["']''', tag, re.IGNORECASE):
            return re.sub(r'''(\bvalue\s*=\s*)("[^"]*"|'[^']*')''',
                          lambda m: m[1] + hide(m[2]), tag, flags=re.IGNORECASE)
        return tag

    text = re.sub(
        r"<(?:parameter|argument|item)\b[^>]*>", xml_attributes, text, flags=re.IGNORECASE,
    )
    text = redact_secrets(text)[0] or ""
    for i, placeholder in enumerate(placeholders):
        text = text.replace(f"~P{i}~", placeholder)
    return text


def _get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


class RepositoryEvidence:
    """Share across workers with distinct packages; package lists own all state."""

    def __init__(self, source: SourceResolver, max_chars: int = 32000):
        self.source = source
        self.max_chars = max(0, max_chars)

    @staticmethod
    def _note(pkg, text):
        text = _redact(text)
        if text not in pkg.context_notes:
            pkg.context_notes.append(text)

    @staticmethod
    def _safe(path: Path, root: Path) -> bool:
        try:
            relative = path.relative_to(root)
            for part in relative.parts:
                name = part.lower()
                if (name in _EXCLUDED or
                        name.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")) or
                        name.startswith((".env", "id_rsa", "id_ed25519", "credentials"))):
                    return False
            cursor = root
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    return False
            return (
                path.suffix.lower() in _EXTENSIONS
                or path.name.lower() in _SPECIAL_FILES
                or any(part.lower() in {".github", ".gitlab"} for part in relative.parts)
            ) and stat.S_ISREG(path.stat().st_mode)
        except (OSError, ValueError):
            return False

    def _resolve(self, pkg, raw) -> Path | None:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            self._note(pkg, "Read rejected: invalid source path.")
            return None
        path = Path(raw.replace("\\", "/"))
        if ".." in path.parts:
            self._note(pkg, "Read rejected: traversal path.")
            return None
        candidates = []
        if path.is_absolute():
            candidates.append(path)
            # The only virtual mount mapping: /src/foo -> <source root>/foo.
            if path.parts[:2] == ("/", "src") and not path.exists():
                candidates.extend(root / Path(*path.parts[2:]) for root in self.source.roots)
        else:
            candidates.extend(root / path for root in self.source.roots)
        for candidate in candidates:
            for root in self.source.roots:
                if self._safe(candidate, root):
                    return candidate.resolve()
        self._note(pkg, "Source path unavailable, excluded, unreadable, or outside configured roots.")
        return None

    def _paths(self, pkg):
        paths = set()
        entries = 0

        def error(_):
            self._note(pkg, "Repository traversal encountered an unreadable directory.")

        walks = [(root, start) for root in self.source.roots
                 for start in (root / "config" / "packages", root / "config", root)
                 if start.is_dir() and not start.is_symlink()
                 and (start == root or not (root / "config").is_symlink())]
        for root, start in walks:
            for directory, dirs, files in os.walk(start, followlinks=False, onerror=error):
                entries += 1 + len(dirs) + len(files)
                if entries > MAX_ENTRIES:
                    self._note(pkg, "Repository traversal truncated at entry limit.")
                    return sorted(paths, key=self._priority)
                dirs[:] = sorted(
                    (d for d in dirs if d.lower() not in _EXCLUDED and not d.lower().startswith(".env")
                     and not (Path(directory) == root and d == "config")
                     and not (Path(directory) == root / "config" and d == "packages")
                     and not (Path(directory) / d).is_symlink()),
                    key=lambda d: (d not in {"config", "packages"}, d),
                )
                for name in sorted(files, key=lambda name: self._priority(Path(directory) / name)):
                    path = Path(directory) / name
                    if self._safe(path, root):
                        paths.add(path)
                        if len(paths) >= MAX_FILES:
                            self._note(pkg, "Repository traversal truncated at file limit.")
                            return sorted(paths, key=self._priority)
        return sorted(paths, key=self._priority)

    @staticmethod
    def _priority(path):
        parts = path.parts
        priority = 4
        if "config" in parts:
            priority = {"security": 0, "framework": 1, "api_platform": 2}.get(path.stem, 3)
        return priority, str(path)

    def _load(self, pkg, path, remaining):
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or size > remaining:
                self._note(pkg, "Source reading truncated at file or total byte limit.")
                return None, 0
            # A bounded read also handles files growing since stat().
            with path.open("rb") as stream:
                data = stream.read(min(MAX_FILE_BYTES, remaining) + 1)
            if len(data) > min(MAX_FILE_BYTES, remaining):
                self._note(pkg, "Source reading truncated at file or total byte limit.")
                return None, len(data)
        except OSError:
            self._note(pkg, "Source file unreadable; no evidence collected from it.")
            return None, 0
        text = data.decode("utf-8", errors="replace")
        if "\x00" in text or re.search(r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)", text):
            self._note(pkg, "Binary or PEM source content excluded.")
            return None, len(data)
        return _redact(text).splitlines(), len(data)

    def _add(self, pkg, path, lines, lo, hi, label="source", limit=None) -> bool:
        header = _redact("File: " + json.dumps(str(path), ensure_ascii=True))
        covered = set()
        for block in pkg.evidence_blocks:
            if block.split("\n", 1)[0] == header:
                covered.update(int(n) for n in re.findall(r"^(\d+) \|", block, re.MULTILINE))
        selected = [n for n in range(max(1, lo), min(len(lines), hi) + 1) if n not in covered]
        if not selected:
            return False
        remaining = min(self.max_chars, limit if limit is not None else self.max_chars) - sum(map(len, pkg.evidence_blocks))
        block = header + "\n[" + _redact(label) + "]"
        added = False
        for n in selected:
            row = f"\n{n} | {lines[n - 1]}"
            if len(block) + len(row) > remaining:
                self._note(pkg, "Repository evidence truncated at character budget.")
                break
            block += row
            added = True
        if added:
            pkg.evidence_blocks.append(block)
            if path.suffix.lower() in _CODE_EXTENSIONS:
                pkg.repository_code_collected = True
        return added

    def enrich(self, pkg, finding, chain=None) -> None:
        self._note(pkg, _STATIC_NOTE)
        limit = self.max_chars * 3 // 4
        locations = []
        flow = _get(chain, "dataflow")
        if flow:
            locations.extend([(_get(flow, "source_file"), _get(flow, "source_line")),
                              (_get(flow, "file"), _get(flow, "line"))])
        for hit in (_get(_get(chain, "presence"), "hits", []) or [])[:MAX_LOCATIONS]:
            locations.append((_get(hit, "file"), _get(hit, "line")))
        locations.extend((_get(_get(chain, "reachability"), "sites", []) or [])[:MAX_LOCATIONS])
        code = _get(finding, "code_context")
        if code:
            locations.append((_get(code, "file_path"), _get(code, "start_line")))
        for step in (_get(finding, "trace", []) or [])[:MAX_LOCATIONS]:
            locations.append((_get(step, "file_path"), _get(step, "line")))
        if len(locations) > MAX_LOCATIONS:
            self._note(pkg, "Source locations truncated at location limit.")
        remaining = MAX_TOTAL_BYTES
        for raw, line in locations[:MAX_LOCATIONS]:
            if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                continue
            path = self._resolve(pkg, raw)
            if path:
                lines, used = self._load(pkg, path, remaining)
                remaining = max(0, remaining - used)
                if lines is not None:
                    self._add(pkg, path, lines, line - 16, line + 16, limit=limit)
        for path in self._paths(pkg):
            if sum(map(len, pkg.evidence_blocks)) >= limit:
                self._note(pkg, "Repository evidence truncated at character budget.")
                break
            relative = next(path.relative_to(root) for root in self.source.roots if path.is_relative_to(root))
            parts = relative.parts
            config = parts[0] == "config" and (
                (len(parts) > 2 and parts[1] in {"packages", "routes", "api_platform"}) or
                path.stem in {"routes", "services"})
            resource = path.suffix.lower() in {".php", ".yaml", ".yml", ".xml"}
            special = path.name.lower() in _SPECIAL_FILES or any(
                part.lower() in {".github", ".gitlab"} for part in parts
            )
            if not config and not resource and not special:
                continue
            lines, used = self._load(pkg, path, remaining)
            remaining = max(0, remaining - used)
            if lines is None:
                continue
            if config:
                label = "static config"
                if len(parts) > 3 and parts[1] == "packages":
                    label += "; environment override: " + parts[2]
                self._add(pkg, path, lines, 1, 80, label, limit=limit)
                if len(lines) > 80:
                    self._note(pkg, "Configuration window truncated to 80 lines; imports are not followed.")
            elif special:
                label = "deployment/build evidence"
                # Extract CGO_ENABLED and Go version for deployment gate checks
                if path.name.lower().startswith("dockerfile"):
                    for line_text in lines:
                        if "CGO_ENABLED" in line_text:
                            label += f" (CGO config: {line_text.strip()})"
                            break
                    for line_text in lines:
                        if re.search(r'\bFROM\s+golang:', line_text, re.IGNORECASE):
                            label += f" (Go build image: {line_text.strip()})"
                            break
                self._add(pkg, path, lines, 1, 120, label, limit=limit)
                if len(lines) > 120:
                    self._note(pkg, "Deployment/build file truncated to 120 lines.")
            elif resource:
                matches = 0
                for n, text in enumerate(lines, 1):
                    if re.search(r"\bApiResource\b|<resources\b|^\s*resources\s*:", text, re.IGNORECASE):
                        self._add(pkg, path, lines, n - 16, n + 16, "static API Platform resource", limit=limit)
                        matches += 1
                        if matches >= MAX_LOCATIONS:
                            self._note(pkg, "Resource windows truncated at match limit.")
                            break

    def retrieve(self, pkg, requests: list[dict]) -> bool:
        self._note(pkg, _STATIC_NOTE)
        if len(requests) > 6:
            self._note(pkg, "Retrieval truncated to six requests per round.")
        added = False
        remaining = MAX_TOTAL_BYTES
        cache = {}

        def load(path):
            nonlocal remaining
            path = path.resolve()
            if path not in cache:
                cache[path], used = self._load(pkg, path, remaining)
                remaining = max(0, remaining - used)
            return cache[path]

        # Explicit locations take precedence over speculative repository searches.
        for request in sorted(requests[:6], key=lambda r: _get(r, "action") != "read"):
            if sum(map(len, pkg.evidence_blocks)) >= self.max_chars:
                self._note(pkg, "Repository evidence truncated at character budget.")
                break
            if not isinstance(request, dict):
                self._note(pkg, "Invalid repository evidence request.")
                continue
            action = request.get("action")
            if action == "read":
                line = request.get("line", 1)
                if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                    self._note(pkg, "Read rejected: line must be a positive integer.")
                    continue
                path = self._resolve(pkg, request.get("path"))
                if path:
                    lines = load(path)
                    if lines is not None:
                        if line > len(lines):
                            self._note(pkg, "Requested line is outside the source file.")
                        added = self._add(pkg, path, lines, line, line + 79) or added
                        if len(lines) > line + 79:
                            self._note(pkg, "Read window truncated to 80 lines.")
            elif action == "search":
                pattern = request.get("pattern")
                if not isinstance(pattern, str) or not pattern or len(pattern) > 512 or "\n" in pattern:
                    self._note(pkg, "Search rejected: expected a nonempty literal of at most 512 characters.")
                    continue
                matches = 0
                for path in self._paths(pkg):
                    lines = load(path)
                    if lines is not None:
                        for n, text in enumerate(lines, 1):
                            if pattern in text:
                                added = self._add(pkg, path, lines, n - 10, n + 10) or added
                                matches += 1
                                if matches >= MAX_LOCATIONS:
                                    break
                    if matches >= MAX_LOCATIONS:
                        self._note(pkg, "Search windows truncated at match limit.")
                        break
            else:
                self._note(pkg, "Unknown repository evidence action; only read and literal search are supported.")
        return added
