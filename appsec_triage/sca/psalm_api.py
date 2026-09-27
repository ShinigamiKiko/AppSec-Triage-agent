"""Psalm answers the dependency questions about a vulnerable PHP method."""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from xml.sax.saxutils import quoteattr

from .. import timing
from .codeql_api import ApiAnswer, Target, _hit
from .codeql_reach import Reached

log = logging.getLogger(__name__)

SUPPORTED_ECOSYSTEMS = frozenset({"composer", "packagist", "php"})
ENGINE = "Psalm"
_TIMEOUT_S = 1800
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# `--find-references-to` analyses the whole project for one method, and the entry lists
# of one package's advisories overlap almost entirely (73-85 methods each for Twig).
# The project does not change during a scan, so one answer per method holds for the run.
_REFERENCES: dict[tuple[str, str], list[tuple[str, int]]] = {}
_REFERENCES_PENDING: dict[tuple[str, str], threading.Event] = {}
_REFERENCES_LOCK = threading.Lock()
# One Psalm on a large project holds several GB (3.3 GB for a reference search over 3400
# files and their vendor tree, more for taint analysis), and three at once froze a 15 GB
# machine. No guess per process: as many at once as the memory holds by the largest
# Psalm this run has measured, one at a time until one has finished.
# APPSEC_PSALM_PARALLEL sets the number by hand.
_PSALM_RESERVE = 3 << 30
_PSALM_FLOOR = 1 << 30
_GATE = threading.Condition()
_RUNNING = 0
# The most one analysis held, its worker processes included: Psalm's `--threads` forks
# workers, and the largest single process no longer says what a run costs.
_PEAK_RUN = 0
_SAMPLER: threading.Thread | None = None
# Workers per analysis: the CPUs shared among the analyses running. Psalm merges the
# workers' call locations and taint graphs into the main process, so the index and the
# paths come out the same; a single thread left 23 of 24 cores idle on api-develop.
_MAX_THREADS = 8
_MEASURED = False
_ANNOUNCED = 0
# A crash exits 1, the code Psalm also uses for "issues found": told apart by its text,
# or an analysis that died reads as "no calls, no path" — a closure nobody checked.
_CRASHED = "crashed due to an uncaught Throwable"
_CRASH_FILE = re.compile(r"in (/[^\s:()]+\.php):\d+")
# Project files Psalm cannot read (a docblock it cannot parse kills the whole run): left
# out of every later run over that project, by the scan and the dependency chain alike.
_UNREADABLE: dict[str, set[str]] = {}
_UNREADABLE_LOCK = threading.Lock()
MAX_UNREADABLE = 5
# Leaving such a file out is not enough: a class another file uses is read through the
# autoloader all the same. Its code, without the docblocks, goes into an overlay the
# analysis takes as a project file, so the class is known and the original never opened.
_OVERLAY: dict[str, Path] = {}
_OVERLAY_PREFIX = "sca-psalm-overlay-"
_DOCBLOCK = re.compile(r"/\*\*.*?\*/", re.S)

# The first path from input to each method, or None: a path into one method does not
# depend on which other methods the stub marks as sinks, so it too holds for the run —
# and one analysis answers for any number of methods. The methods asked for while an
# analysis waits for room in `_slot` join it (`_TAINT_NEXT`): eight findings queued
# behind one Psalm cost two or three analyses, not eight. A method already in an
# analysis is waited for (`_TAINT_PENDING`), never computed twice.
_TAINT: dict[tuple[str, str], Reached | None] = {}
_TAINT_PENDING: dict[tuple[str, str], "_TaintRun"] = {}
_TAINT_NEXT: dict[str, "_TaintRun"] = {}
_TAINT_LOCK = threading.Lock()

# Where every method is called, from one analysis per run. Psalm keeps the call sites of
# all methods once `--find-references-to` switches location collection on;
# `findReferencesToSymbol(m)` reads that table one method at a time, and this plugin
# writes out the whole of it — the same answers as a search per method, for one
# analysis instead of one per finding. The table is Psalm's internal one, read by
# reflection: when a Psalm release renames it, the plugin says so and every method is
# searched on its own, as before.
_INDEX_PLUGIN = r"""<?php
use Psalm\Plugin\EventHandler\AfterAnalysisInterface;
use Psalm\Plugin\EventHandler\Event\AfterAnalysisEvent;

final class ScaCallIndex implements AfterAnalysisInterface
{
    public static function afterAnalysis(AfterAnalysisEvent $event): void
    {
        $out = ['error' => '', 'methods' => [], 'classes' => []];
        try {
            $provider = $event->getCodebase()->file_reference_provider;
            foreach (['methods' => 'class_method_locations', 'classes' => 'class_locations'] as $key => $name) {
                $table = new \ReflectionProperty(get_class($provider), $name);
                foreach ((array) $table->getValue() as $symbol => $locations) {
                    foreach ($locations as $location) {
                        $out[$key][$symbol][] = [$location->file_path, $location->getLineNumber()];
                    }
                }
            }
        } catch (\Throwable $e) {
            $out['error'] = get_class($e) . ': ' . $e->getMessage();
        }
        file_put_contents(%(output)s, json_encode($out, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES));
    }
}
"""
# Any method name switches the collection on; this one has no calls to print.
_INDEX_PROBE = "ScaCallIndex\\Probe::probe"
_INDEX_HOME: Path | None = None
_INDEX_LOCK = threading.Lock()


@dataclass(eq=False)
class _Index:
    """The call sites of every method, by lower-case method id; None when the build failed."""

    methods: dict[str, list[tuple[str, int]]] | None = None
    classes: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    problem: str = ""
    done: threading.Event = field(default_factory=threading.Event)


_INDEXES: dict[str, _Index] = {}

_REFERENCE = re.compile(r"^(?P<file>\S+\.php):(?P<line>\d+)$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CLASS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\\[A-Za-z_][A-Za-z0-9_]*)*$")
_TAINT_RULE = "TaintedEval"

_SIGNATURES_PHP = r"""<?php
$root = $argv[1] ?? '';
$targets = json_decode((string) file_get_contents($argv[2] ?? ''), true) ?: [];
$autoload = rtrim($root, '/') . '/vendor/autoload.php';
if (!is_file($autoload)) {
    echo json_encode(['error' => 'no vendor/autoload.php in the project', 'targets' => []]);
    exit(0);
}
require $autoload;
$out = [];
foreach ($targets as $target) {
    [$class, $method] = $target;
    $row = ['class' => $class, 'method' => $method, 'kind' => 'function', 'static' => false,
            'declaring' => '', 'params' => [], 'error' => ''];
    try {
        if ($class === '') {
            $ref = new ReflectionFunction($method);
            $row['declaring'] = $ref->getName();
        } else {
            $ref = new ReflectionMethod($class, $method);
            $owner = $ref->getDeclaringClass();
            $row['static'] = $ref->isStatic();
            $row['declaring'] = $owner->getName();
            $row['kind'] = $owner->isInterface() ? 'interface' : ($owner->isTrait() ? 'trait' : 'class');
        }
        foreach ($ref->getParameters() as $param) {
            $row['params'][] = ['name' => $param->getName(), 'variadic' => $param->isVariadic(),
                                'optional' => $param->isOptional()];
        }
    } catch (Throwable $e) {
        $row['error'] = get_class($e) . ': ' . $e->getMessage();
    }
    $out[] = $row;
}
echo json_encode(['error' => '', 'targets' => $out]);
"""


@dataclass(slots=True)
class Signature:
    """One method as the installed library declares it."""

    label: str
    function: str
    declaring: str
    kind: str = "class"
    static: bool = False
    params: list[dict] = field(default_factory=list)


def crash_cause(text: str) -> str:
    """The line of a Psalm crash that says what broke; "" when Psalm did not crash."""
    if _CRASHED not in (text or ""):
        return ""
    return next((line.strip() for line in text.splitlines() if "Uncaught" in line), "Psalm crashed")


def exclude_crashed_file(project: Path | str, text: str) -> str:
    """Leave out the project file a crash names; its project-relative path, or "".

    "" also when the file is already left out or too many are: then the crash is not
    one file's fault, and the run reports it instead of shrinking the project further.
    """
    project = Path(project).resolve()
    for relative in _crashed_files(project, text):
        with _UNREADABLE_LOCK:
            known = _UNREADABLE.setdefault(str(project), set())
            if relative in known or len(known) >= MAX_UNREADABLE:
                return ""
            known.add(relative)
        _overlay_copy(project, relative)
        return relative
    return ""


def _crashed_files(project: Path, text: str) -> list[str]:
    """The project files a crash names, relative to the project; vendor and node_modules aside."""
    cause = crash_cause(text) or ("Uncaught" in (text or "") and text) or ""
    files: list[str] = []
    for match in _CRASH_FILE.finditer(cause):
        try:
            relative = Path(match.group(1)).resolve().relative_to(project)
        except (ValueError, OSError):
            continue
        if relative.parts and relative.parts[0] not in ("vendor", "node_modules"):
            files.append(relative.as_posix())
    return files


def _overlay_copy(project: Path, relative: str) -> None:
    """The file's code without its docblocks, at the same relative path in the overlay."""
    try:
        text = (project / relative).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    with _UNREADABLE_LOCK:
        base = _OVERLAY.get(str(project))
        if base is None:
            base = Path(tempfile.mkdtemp(prefix=_OVERLAY_PREFIX))
            atexit.register(shutil.rmtree, base, True)
            _OVERLAY[str(project)] = base
    copy = base / relative
    copy.parent.mkdir(parents=True, exist_ok=True)
    # Each docblock becomes as many empty lines as it had: a finding in the copy keeps
    # the line number it has in the original.
    copy.write_text(_DOCBLOCK.sub(lambda m: "\n" * m.group(0).count("\n"), text), encoding="utf-8")


def overlay_dir(project: Path | str) -> Path | None:
    with _UNREADABLE_LOCK:
        return _OVERLAY.get(str(Path(project).resolve()))


def original_path(path: str) -> str | None:
    """A path inside an overlay → the project-relative path of the file it stands for."""
    normal = (path or "").replace("\\", "/")
    at = normal.find("/" + _OVERLAY_PREFIX)
    if at < 0:
        return None
    rest = normal[at + 1:].split("/", 1)
    return rest[1] if len(rest) == 2 and rest[1] else None


def unreadable_files(project: Path | str) -> list[str]:
    with _UNREADABLE_LOCK:
        return sorted(_UNREADABLE.get(str(Path(project).resolve()), ()))


def _clean_class(klass: str) -> str:
    return (klass or "").strip().lstrip("\\")


def targets_valid(targets: list[Target]) -> list[Target]:
    return [t for t in targets
            if t.function and _IDENTIFIER.match(t.function)
            and (not t.klass or _CLASS_NAME.match(_clean_class(t.klass)))]


def stub(signatures: list[Signature]) -> str:
    """A stub declaring every parameter of these methods as an `eval` taint sink."""
    grouped: dict[str, dict[tuple[str, str], list[Signature]]] = {}
    for sig in signatures:
        namespace, _, short = sig.declaring.rpartition("\\")
        if sig.kind == "function":
            grouped.setdefault(namespace, {}).setdefault(("function", ""), []).append(sig)
        else:
            grouped.setdefault(namespace, {}).setdefault((sig.kind, short), []).append(sig)

    lines = ["<?php", "// Generated for dependency triage: parameters of vulnerable methods as taint sinks."]
    for namespace, owners in grouped.items():
        lines.append(f"namespace {namespace} {{" if namespace else "namespace {")
        for (kind, short), methods in owners.items():
            indent = "    " if kind != "function" else ""
            if kind != "function":
                lines.append(f"{kind} {short} {{")
            for sig in methods:
                params, docs = [], []
                for param in sig.params:
                    name = str(param.get("name") or "")
                    if not _IDENTIFIER.match(name):
                        continue
                    docs.append(f"{indent} * @psalm-taint-sink eval ${name}")
                    if param.get("variadic"):
                        params.append(f"...${name}")
                    else:
                        params.append(f"${name}" + (" = null" if param.get("optional") else ""))
                name = sig.declaring.rpartition("\\")[2] if kind == "function" else sig.function
                body = ";" if kind == "interface" else " {}"
                modifiers = "" if kind == "function" else "public " + ("static " if sig.static else "")
                lines += [f"{indent}/**", *docs, f"{indent} */",
                          f"{indent}{modifiers}function {name}({', '.join(params)}){body}"]
            if kind != "function":
                lines.append("}")
        lines.append("}")
    return "\n".join(lines) + "\n"


_NAMESPACE = re.compile(r"^\s*namespace\s+([A-Za-z_][\w\\]*)\s*[;{]", re.MULTILINE)
_DECLARATION = re.compile(r"^\s*(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\s+([A-Za-z_]\w*)",
                          re.MULTILINE)
_MAX_QUALIFIED = 8
_MAX_PACKAGE_FILES = 4000


def qualify(project_root: Path | str, package: str, names: list[str]) -> dict[str, list[str]]:
    """Fully qualified classes of the installed `package` that declare each method name."""
    from ..testpaths import is_test

    package_dir = Path(project_root) / "vendor" / package
    wanted = [name for name in dict.fromkeys(names) if _IDENTIFIER.match(name or "")]
    found: dict[str, list[str]] = {name: [] for name in wanted}
    if not wanted or not package_dir.is_dir():
        return found
    patterns = {name: re.compile(rf"\bfunction\s+&?{re.escape(name)}\s*\(") for name in wanted}
    for index, path in enumerate(sorted(package_dir.rglob("*.php"))):
        if index >= _MAX_PACKAGE_FILES:
            break
        if is_test(path.relative_to(package_dir).as_posix()):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        declaration = _DECLARATION.search(text)
        if declaration is None:
            continue
        namespace = _NAMESPACE.search(text)
        fqcn = f"{namespace.group(1)}\\{declaration.group(1)}" if namespace else declaration.group(1)
        for name, pattern in patterns.items():
            if len(found[name]) < _MAX_QUALIFIED and fqcn not in found[name] and pattern.search(text):
                found[name].append(fqcn)
    return found


_PUBLIC_METHOD = re.compile(
    r"^\s*(?:(?:abstract|final|static)\s+)*(?:public\s+)?(?:(?:abstract|final|static)\s+)*"
    r"function\s+&?([A-Za-z_]\w*)\s*\(",
    re.MULTILINE)


def public_api(project_root: Path | str, package: str, limit: int = 40) -> str:
    """The installed package's public methods, as a line the model chooses its questions from."""
    from ..testpaths import is_test

    package_dir = Path(project_root) / "vendor" / package
    if not package or not package_dir.is_dir():
        return ""
    entries: list[str] = []
    php_files = sorted(package_dir.rglob("*.php"), key=lambda p: (len(p.relative_to(package_dir).parts), str(p)))
    for index, path in enumerate(php_files):
        if index >= _MAX_PACKAGE_FILES:
            break
        if is_test(path.relative_to(package_dir).as_posix()):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        declaration = _DECLARATION.search(text)
        if declaration is None:
            continue
        namespace = _NAMESPACE.search(text)
        fqcn = f"{namespace.group(1)}\\{declaration.group(1)}" if namespace else declaration.group(1)
        for name in dict.fromkeys(_PUBLIC_METHOD.findall(text)):
            if name.startswith("__"):
                continue
            entries.append(f"{fqcn}::{name}")
    entries = entries[:limit]
    if not entries:
        return ""
    return ("Public methods of the installed package (its API, read from vendor/; not evidence about this "
            "project): " + ", ".join(entries) + ". A fix often names an internal helper no application "
            "calls — ask about the public methods that lead to it.")


def _relative(path: str, base: Path, project: Path) -> str | None:
    """A Psalm path — relative to its working directory — as a path inside the project."""
    if (original := original_path(path)) is not None:
        return original
    candidate = Path(path)
    resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    try:
        return resolved.relative_to(project).as_posix()
    except ValueError:
        return None


def parse_references(output: str, base: Path, project: Path) -> list[tuple[str, int]]:
    sites: list[tuple[str, int]] = []
    for raw in output.splitlines():
        match = _REFERENCE.match(_ANSI.sub("", raw).strip())
        if match is None:
            continue
        file = _relative(match.group("file"), base, project)
        site = (file, int(match.group("line"))) if file else None
        if site and site not in sites:
            sites.append(site)
    return sites


def parse_taint(document: dict, base: Path, project: Path, signatures: list[Signature],
                references: dict[str, list[tuple[str, int]]]) -> dict[str, Reached]:
    """The first path per method, keeping only our sinks: `TaintedEval` on a line calling the method."""
    found: dict[str, Reached] = {}
    for run_ in document.get("runs") or []:
        names = {str(rule.get("id")): str(rule.get("name") or "")
                 for rule in ((run_.get("tool") or {}).get("driver") or {}).get("rules") or []}
        for result in run_.get("results") or []:
            rule = names.get(str(result.get("ruleId")), str(result.get("ruleId") or ""))
            message = ((result.get("message") or {}).get("text") or "").lower()
            if rule != _TAINT_RULE and not (not names and "passed to eval" in message):
                continue
            physical = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            sink_file = _relative((physical.get("artifactLocation") or {}).get("uri") or "", base, project)
            sink_line = (physical.get("region") or {}).get("startLine")
            if not sink_file or not isinstance(sink_line, int):
                continue
            enclosing = _enclosing_call(project, sink_file, sink_line, signatures, references)
            if enclosing is None:
                continue
            chosen, call_line = enclosing
            if chosen.label in found:
                continue
            steps: list[str] = []
            for flow in (result.get("codeFlows") or [])[:1]:
                for thread in (flow.get("threadFlows") or [])[:1]:
                    for step in thread.get("locations") or []:
                        loc = (step.get("location") or {}).get("physicalLocation") or {}
                        file = _relative((loc.get("artifactLocation") or {}).get("uri") or "", base, project)
                        line = (loc.get("region") or {}).get("startLine")
                        if file and isinstance(line, int):
                            entry = f"{file}:{line}"
                            if not steps or steps[-1] != entry:
                                steps.append(entry)
            source = steps[0].rsplit(":", 1) if steps else (sink_file, str(call_line))
            found[chosen.label] = Reached(sink_file, call_line, source[0], int(source[1]),
                                          steps=steps, engine=ENGINE)
    return found


_MAX_CALL_LINES = 40


def _call_end(lines: list[str], start: int, function: str) -> int:
    """The last line (1-based) of the call to `function` that begins on line `start`."""
    if not 0 < start <= len(lines):
        return start
    chunk = "\n".join(lines[start - 1:start - 1 + _MAX_CALL_LINES])
    match = re.search(rf"(?<![\w$]){re.escape(function)}\s*\(", chunk, re.IGNORECASE)
    if match is None or "\n" in chunk[:match.start()]:
        return start
    depth, quote, escaped = 0, "", False
    for index in range(match.end() - 1, len(chunk)):
        char = chunk[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return start + chunk.count("\n", 0, index)
    return start


def _enclosing_call(project: Path, sink_file: str, sink_line: int, signatures: list[Signature],
                    references: dict[str, list[tuple[str, int]]]) -> tuple[Signature, int] | None:
    """(method, line the call starts on) for a sink Psalm reported inside one of our calls."""
    try:
        lines = (project / sink_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    best: tuple[Signature, int] | None = None
    for sig in signatures:
        for file, line in references.get(sig.label, []):
            if file != sink_file or line > sink_line:
                continue
            if sink_line <= _call_end(lines, line, sig.function) and (best is None or line > best[1]):
                best = (sig, line)
    if best is not None:
        return best
    text = lines[sink_line - 1] if 0 < sink_line <= len(lines) else ""
    for sig in signatures:
        if re.search(rf"(?<![\w$]){re.escape(sig.function)}\s*\(", text, re.IGNORECASE):
            return sig, sink_line
    return None


def _config(path: Path, project: Path, stub_path: Path | None = None, cache: Path | None = None) -> Path:
    autoload = project / "vendor" / "autoload.php"
    vendor = project / "vendor"
    ignored = "".join(f"<file name={quoteattr(str(project / name))} />"
                      for name in unreadable_files(project) if (project / name).is_file())
    overlay = overlay_dir(project)
    parts = [
        '<?xml version="1.0"?>',
        '<psalm xmlns="https://getpsalm.org/schema/config" errorLevel="8" findUnusedCode="false"'
        + (f" autoloader={quoteattr(str(autoload))}" if autoload.is_file() else "")
        + (f" cacheDirectory={quoteattr(str(cache))}" if cache is not None else "") + ">",
        f"  <projectFiles><directory name={quoteattr(str(project))} />"
        + (f"<directory name={quoteattr(str(overlay))} />" if overlay is not None else "")
        + ""
        + (f"<ignoreFiles>{f'<directory name={quoteattr(str(vendor))} />' if vendor.is_dir() else ''}"
           f"{ignored}</ignoreFiles>" if vendor.is_dir() or ignored else "")
        + "</projectFiles>",
    ]
    if stub_path is not None:
        parts.append(f"  <stubs><file name={quoteattr(str(stub_path))} /></stubs>")
    parts.append("</psalm>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path


def _php_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _index_home(project: Path) -> Path:
    """The run's directory for the call index of this project: config, plugin, output, cache."""
    global _INDEX_HOME
    with _INDEX_LOCK:
        if _INDEX_HOME is None:
            _INDEX_HOME = Path(tempfile.mkdtemp(prefix="sca-psalm-index-"))
            atexit.register(shutil.rmtree, _INDEX_HOME, True)
        home = _INDEX_HOME / re.sub(r"[^\w.-]+", "_", str(project)).strip("_")[-80:]
    (home / "cache").mkdir(parents=True, exist_ok=True)
    return home


def _build_index(project: Path, binary: str, timeout_s: float) -> tuple[dict[str, list[tuple[str, int]]] | None,
                                                                        dict[str, list[tuple[str, int]]], str]:
    """(method id -> call sites, class -> reference sites, "") from one analysis, or (None, {}, problem).

    Ids are lower-case, as Psalm keeps them."""
    home = _index_home(project)
    config = _config(home / "psalm.xml", project, cache=home / "cache")
    result, plugin = home / "calls.json", home / "ScaCallIndex.php"
    result.unlink(missing_ok=True)
    plugin.write_text(_INDEX_PLUGIN % {"output": _php_string(str(result))}, encoding="utf-8")
    started = time.monotonic()
    _, problem = _psalm([binary, f"--config={config}", f"--root={project}", "--no-progress",
                         f"--find-references-to={_INDEX_PROBE}", f"--plugin={plugin}"],
                        home, timeout_s, "индекс вызовов")
    if problem:
        return None, {}, problem
    try:
        payload = json.loads(result.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, {}, f"индекс вызовов не прочитан: {exc}"
    if not isinstance(payload, dict) or payload.get("error") or not isinstance(payload.get("methods"), dict):
        error = payload.get("error") if isinstance(payload, dict) else ""
        return None, {}, f"индекс вызовов не собран: {error or 'нет таблицы вызовов'}"
    places: dict[str, str | None] = {}

    def table(raw_table) -> dict[str, list[tuple[str, int]]]:
        out: dict[str, list[tuple[str, int]]] = {}
        for symbol, rows in (raw_table.items() if isinstance(raw_table, dict) else ()):
            sites: dict[tuple[str, int], None] = {}
            for row in rows if isinstance(rows, list) else ():
                if not (isinstance(row, list) and len(row) == 2 and isinstance(row[1], int)):
                    continue
                raw = str(row[0])
                if raw not in places:
                    places[raw] = _relative(raw, home, project)
                if places[raw]:
                    sites[(places[raw], row[1])] = None
            out[str(symbol).lower()] = list(sites)
        return out

    index, classes = table(payload["methods"]), table(payload.get("classes"))
    log.info("psalm api: call index of %s: %d method(s) called at %d site(s), %d class(es) referenced, "
             "built in %.0fs", project.name, len(index), sum(len(v) for v in index.values()), len(classes),
             time.monotonic() - started)
    return index, classes, ""


def _call_index(project: Path, binary: str, timeout_s: float) -> _Index:
    """The project's call index: the first asker builds it, the rest wait for that build."""
    key = str(project)
    with _INDEX_LOCK:
        index = _INDEXES.get(key)
        build = index is None
        if build:
            index = _INDEXES[key] = _Index()
    if not build:
        with timing.measure("psalm-wait"):
            index.done.wait()
        return index
    try:
        index.methods, index.classes, index.problem = _build_index(project, binary, timeout_s)
    except Exception as exc:  # noqa: BLE001 - the askers fall back to one search per method
        log.exception("psalm api: call index failed")
        index.problem = f"индекс вызовов: {exc}"
    finally:
        if index.methods is None:
            log.info("psalm api: no call index (%s); methods are searched one by one", index.problem[:300])
            if crash_cause(index.problem):
                # `run` leaves the file out and asks again: built again, without it.
                with _INDEX_LOCK:
                    if _INDEXES.get(key) is index:
                        del _INDEXES[key]
        index.done.set()
    return index


def usages(project_root: Path | str, name: str) -> list[tuple[str, str, int]] | None:
    """(symbol, file, line) where the project calls a method or refers to a class of this name.

    From the call index, so typed like Psalm's own analysis; None when the index is not
    built (yet) for this project — the caller asks elsewhere. `name` is `method`,
    `Class::method`, `Class` or a fully qualified class.
    """
    with _INDEX_LOCK:
        index = _INDEXES.get(str(Path(project_root).resolve()))
    if index is None or not index.done.is_set() or index.methods is None:
        return None
    wanted = str(name or "").strip().lstrip("\\").rstrip("()").lower()
    klass, _, member = wanted.rpartition("::") if "::" in wanted else ("", "", wanted)
    short = re.split(r"\\|\.", member)[-1]
    if not short:
        return []

    def same_class(declared: str) -> bool:
        return not klass or declared == klass or declared.endswith("\\" + klass)

    rows: dict[tuple[str, str, int], None] = {}
    for method, sites in index.methods.items():
        declared, _, function = method.rpartition("::")
        if function == short and same_class(declared):
            rows.update(((method, file, line), None) for file, line in sites)
    if not klass:
        for referenced, sites in index.classes.items():
            if referenced == member or referenced.rpartition("\\")[2] == short:
                rows.update(((referenced, file, line), None) for file, line in sites)
    return sorted(rows, key=lambda row: (row[1], row[2], row[0]))


def prefetch(project_root: Path | str, binary: str, timeout_s: float = _TIMEOUT_S) -> None:
    """Start building the call index now, while the findings' advisories are still being read."""
    project = Path(project_root).resolve()
    if not (project / "vendor" / "autoload.php").is_file():
        return

    def build() -> None:
        for _ in range(MAX_UNREADABLE + 1):
            index = _call_index(project, binary, timeout_s)
            if index.methods is not None or not (skipped := exclude_crashed_file(project, index.problem)):
                return
            log.warning("psalm api: %s left out — Psalm cannot read it; building the call index again", skipped)

    threading.Thread(target=build, name="psalm-call-index", daemon=True).start()


def _references(key: tuple[str, str], compute) -> tuple[list[tuple[str, int]], str]:
    """(references, problem) for one method, computed once per run; a failure is not kept."""
    while True:
        with _REFERENCES_LOCK:
            if key in _REFERENCES:
                return _REFERENCES[key], ""
            pending = _REFERENCES_PENDING.get(key)
            if pending is None:
                pending = _REFERENCES_PENDING[key] = threading.Event()
                break
        pending.wait()
    try:
        found, problem = compute()
        if not problem:
            with _REFERENCES_LOCK:
                _REFERENCES[key] = found
        return found, problem
    finally:
        with _REFERENCES_LOCK:
            _REFERENCES_PENDING.pop(key, None)
        pending.set()


@dataclass(eq=False)
class _TaintRun:
    """One taint analysis; the methods asked for while it waits for Psalm join it."""

    project: Path
    signatures: dict[tuple[str, str], Signature] = field(default_factory=dict)
    references: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    led: bool = False
    problem: str = ""
    done: threading.Event = field(default_factory=threading.Event)


def _join_taint(project: Path, signatures: list[Signature], keys: dict[str, tuple[str, str]],
                references: dict[str, list[tuple[str, int]]]) -> list[_TaintRun]:
    """The analyses that answer these methods, joining the gathering one for methods no analysis has."""
    runs: dict[int, _TaintRun] = {}
    with _TAINT_LOCK:
        for sig in signatures:
            key = keys[sig.label]
            if key in _TAINT:
                continue
            taint_run = _TAINT_PENDING.get(key)
            if taint_run is None:
                taint_run = _TAINT_NEXT.get(str(project))
                if taint_run is None:
                    taint_run = _TAINT_NEXT[str(project)] = _TaintRun(project)
                # One label per method whichever finding asked: the method id itself.
                taint_run.signatures[key] = replace(sig, label=key[1])
                taint_run.references[key[1]] = references.get(sig.label, [])
                _TAINT_PENDING[key] = taint_run
            runs[id(taint_run)] = taint_run
    return list(runs.values())


def _take_part(taint_run: _TaintRun, binary: str, timeout_s: float) -> None:
    """Lead the analysis if nobody does yet, else wait for it."""
    with _TAINT_LOCK:
        lead, taint_run.led = not taint_run.led, True
    if not lead:
        with timing.measure("psalm-wait"):
            taint_run.done.wait()
        return
    project = str(taint_run.project)
    try:
        with _slot():
            with _TAINT_LOCK:
                if _TAINT_NEXT.get(project) is taint_run:
                    del _TAINT_NEXT[project]          # sealed: later askers start the next one
                signatures = list(taint_run.signatures.values())
                references = dict(taint_run.references)
            if len(signatures) > 1:
                log.info("psalm api: one taint analysis for %d method(s)", len(signatures))
            fresh, taint_run.problem = _taint_analysis(signatures, references, taint_run.project,
                                                       binary, timeout_s)
        if not taint_run.problem:
            with _TAINT_LOCK:
                for key, sig in taint_run.signatures.items():
                    _TAINT[key] = fresh.get(sig.label)
    except Exception as exc:  # noqa: BLE001 - the waiters must hear of it, not hang
        log.exception("psalm api: taint analysis failed")
        taint_run.problem = f"taint-анализ: {exc}"
    finally:
        with _TAINT_LOCK:
            if _TAINT_NEXT.get(project) is taint_run:
                del _TAINT_NEXT[project]
            for key in taint_run.signatures:
                if _TAINT_PENDING.get(key) is taint_run:
                    del _TAINT_PENDING[key]
        taint_run.done.set()


def _taint_analysis(signatures: list[Signature], references: dict[str, list[tuple[str, int]]],
                    project: Path, binary: str, timeout_s: float) -> tuple[dict[str, Reached], str]:
    """Taint analysis with these methods as sinks: (first path per label, problem). The caller holds a slot."""
    with tempfile.TemporaryDirectory(prefix="sca-psalm-taint-") as tmp:
        work = Path(tmp)
        # Without Psalm's cache: the stub marks different methods as sinks on every run,
        # and a cached storage could carry the previous run's sinks.
        stub_path = work / "sca-sinks.php"
        stub_path.write_text(stub(signatures), encoding="utf-8")
        taint_config = _config(work / "psalm-taint.xml", project, stub_path)
        report = work / "taint.sarif"
        _, problem = _run([binary, f"--config={taint_config}", f"--root={project}", "--taint-analysis",
                           "--no-cache", "--no-progress", f"--threads={_threads()}", f"--report={report}"],
                          work, timeout_s, "taint-анализ")
        if problem:
            return {}, problem
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {}, f"отчёт taint-анализа не прочитан: {exc}"
        return parse_taint(document, work, project, signatures, references), ""


def _memory_limit() -> int:
    """Bytes this process may use: the container's cgroup limit or the machine's memory; 0 unknown."""
    limits: list[int] = []
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            text = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text.isdigit():
            limits.append(int(text))
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                limits.append(int(line.split()[1]) * 1024)
    except (OSError, ValueError, IndexError):
        pass
    return min(limits) if limits else 0


def _largest_child() -> int:
    """Peak resident size of the largest finished child process, bytes; 0 before one.

    Any child counts, so it is read only after a Psalm of ours has finished: then it is
    at least that Psalm's peak, not a small `composer dump-autoload` that ran before.
    """
    if not _MEASURED:
        return 0
    try:
        import resource
    except ImportError:          # pragma: no cover - not on Linux
        return 0
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024


def _cpu_count() -> int:
    """CPUs this process may use: its affinity and the container's CPU quota."""
    try:
        count = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        count = os.cpu_count() or 1
    quota = 0.0
    try:
        limit, period = Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf-8").split()[:2]
        if limit != "max":
            quota = int(limit) / int(period)
    except (OSError, ValueError):
        try:
            limit = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text(encoding="utf-8"))
            period = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text(encoding="utf-8"))
            if limit > 0 and period > 0:
                quota = limit / period
        except (OSError, ValueError):
            pass
    if quota > 0:
        count = min(count, max(1, int(quota + 0.5)))
    return max(1, count)


def _threads() -> int:
    """Psalm worker processes for the analysis about to start, its slot already taken."""
    raw = os.environ.get("APPSEC_PSALM_THREADS", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    with _GATE:
        running = max(1, _RUNNING)
    return max(1, min(_MAX_THREADS, _cpu_count() // running))


def _psalm_memory() -> int:
    """Resident bytes of the Psalm processes this process started, workers included."""
    me, page = os.getpid(), os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    parents: dict[int, int] = {}
    sizes: dict[int, int] = {}
    try:
        entries = [e.name for e in os.scandir("/proc") if e.name.isdigit()]
    except OSError:
        return 0
    for name in entries:
        try:
            stat = Path(f"/proc/{name}/stat").read_text(encoding="utf-8", errors="replace")
            parents[int(name)] = int(stat.rsplit(")", 1)[1].split()[1])
            if b"psalm" in Path(f"/proc/{name}/cmdline").read_bytes():
                sizes[int(name)] = int(Path(f"/proc/{name}/statm").read_text().split()[1]) * page
        except (OSError, ValueError, IndexError):
            continue
    total = 0
    for pid, size in sizes.items():
        seen, parent = 0, parents.get(pid)
        while parent and parent != me and seen < 64:
            parent, seen = parents.get(parent), seen + 1
        if parent == me:
            total += size
    return total


def _watch_memory() -> None:
    """While Psalm runs: the most one analysis holds, workers included."""
    global _PEAK_RUN, _SAMPLER
    while True:
        with _GATE:
            running = _RUNNING
            if not running:
                _SAMPLER = None
                return
        if total := _psalm_memory():
            _PEAK_RUN = max(_PEAK_RUN, total // running)
        time.sleep(1.0)


def parallel_limit() -> int:
    """How many Psalm processes may run at once: one until one has been measured."""
    raw = os.environ.get("APPSEC_PSALM_PARALLEL", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    memory, peak = _memory_limit(), max(_largest_child(), _PEAK_RUN if _MEASURED else 0)
    if not memory or not peak:
        return 1
    each = max(peak, _PSALM_FLOOR) * 5 // 4
    return max(1, min(os.cpu_count() or 1, (memory - _PSALM_RESERVE) // each))


@contextmanager
def _slot():
    """Room for one Psalm process: a finding waits here rather than running the memory out."""
    global _RUNNING, _ANNOUNCED, _MEASURED, _SAMPLER
    queued = time.monotonic()
    with _GATE:
        while _RUNNING >= (limit := parallel_limit()):
            _GATE.wait()
        if limit != _ANNOUNCED:
            _ANNOUNCED = limit
            log.info("psalm api: up to %d Psalm analysis(es) at once, %d worker(s) each "
                     "(largest so far %.1f GB)", limit, max(1, min(_MAX_THREADS, _cpu_count() // limit)),
                     max(_largest_child(), _PEAK_RUN) / (1 << 30))
        _RUNNING += 1
        if _SAMPLER is None and os.path.isdir("/proc"):
            _SAMPLER = threading.Thread(target=_watch_memory, name="psalm-memory", daemon=True)
            _SAMPLER.start()
    timing.add("psalm-wait", time.monotonic() - queued)
    try:
        with timing.measure("psalm"):
            yield
    finally:
        with _GATE:
            _RUNNING -= 1
            _MEASURED = True
            _GATE.notify_all()


def _psalm(argv: list[str], cwd: Path, timeout_s: float, what: str) -> tuple[str, str]:
    """`_run` for Psalm itself, in a slot."""
    with _slot():
        return _run([*argv, f"--threads={_threads()}"], cwd, timeout_s, what)


def _run(argv: list[str], cwd: Path, timeout_s: float, what: str) -> tuple[str, str]:
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout_s,
                              encoding="utf-8", errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return "", f"{what}: не уложился в {timeout_s}с"
    except OSError as exc:
        return "", f"{what}: не запустился: {exc}"
    if proc.returncode not in (0, 1, 2):
        tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-4:])
        return "", f"{what}: код {proc.returncode}: {tail[:300]}"
    output = proc.stdout + "\n" + proc.stderr
    if cause := crash_cause(output):
        return "", f"{what}: Psalm упал — {cause[:500]}"
    return output, ""


def run(project_root: Path | str, targets: list[Target], *, binary: str = "psalm", php: str = "php",
        timeout_s: float = _TIMEOUT_S) -> ApiAnswer:
    """Find the calls of these PHP methods and the paths from user input into them.

    A file Psalm crashes on is left out and the question asked again: one unreadable
    docblock must not cost every PHP dependency its call search.
    """
    project = Path(project_root).resolve()
    before = set(unreadable_files(project))
    answer = _run_once(project, targets, binary=binary, php=php, timeout_s=timeout_s)
    for _ in range(MAX_UNREADABLE):
        if not answer.problem:
            break
        skipped = exclude_crashed_file(project, answer.problem)
        if not skipped:
            # The analyses are shared: another finding may have left the file out while
            # this one waited for the answer. Then it is worth asking again, once more.
            newly = set(unreadable_files(project)) - before
            skipped = next((f for f in _crashed_files(project, answer.problem) if f in newly), "")
            if not skipped:
                break
        log.warning("psalm api: %s left out — Psalm cannot read it; asking again", skipped)
        before = set(unreadable_files(project))
        answer = _run_once(project, targets, binary=binary, php=php, timeout_s=timeout_s)
    return answer


def _run_once(project: Path, targets: list[Target], *, binary: str, php: str,
              timeout_s: float) -> ApiAnswer:
    targets = targets_valid(targets)
    if not targets:
        return ApiAnswer(problem="нет корректных имён PHP-методов для поиска", engine="psalm")
    if not (project / "vendor" / "autoload.php").is_file():
        return ApiAnswer(problem="в проекте нет vendor/autoload.php — сигнатуры и типы не разрешить",
                         engine="psalm")

    with tempfile.TemporaryDirectory(prefix="sca-psalm-") as tmp:
        work = Path(tmp)
        (work / "signatures.php").write_text(_SIGNATURES_PHP, encoding="utf-8")
        (work / "targets.json").write_text(
            json.dumps([[_clean_class(t.klass), t.function] for t in targets]), encoding="utf-8")
        output, problem = _run([php, str(work / "signatures.php"), str(project), str(work / "targets.json")],
                               work, 120, "чтение сигнатур")
        if problem:
            return ApiAnswer(problem=problem, engine="psalm")
        try:
            payload = json.loads(output.strip().splitlines()[0])
        except (ValueError, IndexError) as exc:
            return ApiAnswer(problem=f"сигнатуры не прочитаны: {exc}", engine="psalm")
        if payload.get("error"):
            return ApiAnswer(problem=f"сигнатуры: {payload['error']}", engine="psalm")

        signatures: list[Signature] = []
        unresolved: list[str] = []
        for target, row in zip(targets, payload.get("targets") or []):
            if row.get("error"):
                unresolved.append(f"{target.label}: {row['error'][:120]}")
                continue
            signatures.append(Signature(target.label, target.function, str(row.get("declaring") or ""),
                                        str(row.get("kind") or "class"), bool(row.get("static")),
                                        list(row.get("params") or [])))
        if not signatures:
            return ApiAnswer(problem="ни один метод не найден в установленных пакетах: " + "; ".join(unresolved),
                             engine="psalm")

        answer = ApiAnswer(engine="psalm")
        references: dict[str, list[tuple[str, int]]] = {}
        base_config = _config(work / "psalm.xml", project)
        index = None
        if any(sig.kind != "function" for sig in signatures):
            index = _call_index(project, binary, timeout_s)
            if index.methods is None and crash_cause(index.problem):
                return ApiAnswer(problem=index.problem, engine="psalm")
        for sig in signatures:
            if sig.kind == "function":
                continue
            method = f"{_clean_class(sig.declaring)}::{sig.function}"
            if index is not None and index.methods is not None:
                references[sig.label] = index.methods.get(method.lower(), [])
            else:
                def find(method=method, sig=sig):
                    output, problem = _psalm([binary, f"--config={base_config}", f"--root={project}",
                                              "--no-cache", "--no-progress",
                                              f"--find-references-to={method}"],
                                             work, timeout_s, f"поиск вызовов {sig.label}")
                    return ([], problem) if problem else (parse_references(output, work, project), "")

                found, problem = _references((str(project), method), find)
                if problem:
                    return ApiAnswer(problem=problem, engine="psalm")
                references[sig.label] = found
            if references[sig.label]:
                answer.calls[sig.label] = [_hit(project, file, line) for file, line in references[sig.label]]

        keys = {sig.label: (str(project), f"{_clean_class(sig.declaring)}::{sig.function}")
                for sig in signatures}
        runs = _join_taint(project, signatures, keys, references)
        # The ones nobody leads yet first: the others are under way without this finding.
        for taint_run in sorted(runs, key=lambda r: r.led):
            _take_part(taint_run, binary, timeout_s)
        if failure := next((r.problem for r in runs if r.problem), ""):
            return ApiAnswer(calls=answer.calls, problem=failure, engine="psalm")
        with _TAINT_LOCK:
            answer.reached = {label: reached for label, key in keys.items()
                              if (reached := _TAINT.get(key)) is not None}
        for label, reached in answer.reached.items():
            site = _hit(project, reached.file, reached.line)
            if all((hit.file, hit.line) != (site.file, site.line) for hit in answer.calls.get(label, [])):
                answer.calls.setdefault(label, []).append(site)

    if unresolved:
        log.info("psalm api: unresolved targets: %s", "; ".join(unresolved))
    log.info("psalm api: %s", ", ".join(
        f"{sig.label}: {len(answer.calls.get(sig.label, []))} calls, "
        f"{'reached' if sig.label in answer.reached else 'not reached'}" for sig in signatures))
    return answer
