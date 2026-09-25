"""Psalm answers the dependency questions about a vulnerable PHP method."""

from __future__ import annotations

import atexit
import json
import logging
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import quoteattr

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

# One batch at a time: a second batch waits and then finds most of its methods cached.
_BATCH_LOCK = threading.Lock()
# The first path from input to each method, or None: a path into one method does not
# depend on which other methods the stub marks as sinks, so it too holds for the run.
_TAINT: dict[tuple[str, str], Reached | None] = {}
_TAINT_LOCK = threading.Lock()
# Batches run one at a time, so they can share Psalm's own cache: the vendor tree is
# parsed once per run instead of once per batch. Its config, plugin and files keep one
# path for the whole run, so Psalm never sees a "new" config and drops the cache.
_BATCH_HOME: Path | None = None

# `--find-references-to` takes one method, but the codebase it analyses answers any
# number: this plugin asks it for all of them once the analysis is done. The CLI option
# still names one method — that is what switches on the collection of call locations.
_REFERENCES_PLUGIN = r"""<?php
use Psalm\Plugin\EventHandler\AfterAnalysisInterface;
use Psalm\Plugin\EventHandler\Event\AfterAnalysisEvent;

final class ScaReferences implements AfterAnalysisInterface
{
    public static function afterAnalysis(AfterAnalysisEvent $event): void
    {
        $codebase = $event->getCodebase();
        $methods = json_decode((string) file_get_contents(%(input)s), true);
        $out = [];
        foreach (is_array($methods) ? $methods : [] as $method) {
            try {
                $out[$method] = array_map(
                    static fn($location) => [$location->file_path, $location->getLineNumber()],
                    $codebase->findReferencesToSymbol($method)
                );
            } catch (\Throwable $e) {
                $out[$method] = ['error' => $e->getMessage()];
            }
        }
        file_put_contents(%(output)s, json_encode($out));
    }
}
"""
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
    cause = crash_cause(text) or ("Uncaught" in (text or "") and text) or ""
    for match in _CRASH_FILE.finditer(cause):
        try:
            relative = Path(match.group(1)).resolve().relative_to(project)
        except (ValueError, OSError):
            continue
        if not relative.parts or relative.parts[0] in ("vendor", "node_modules"):
            continue
        with _UNREADABLE_LOCK:
            known = _UNREADABLE.setdefault(str(project), set())
            if relative.as_posix() in known or len(known) >= MAX_UNREADABLE:
                return ""
            known.add(relative.as_posix())
        _overlay_copy(project, relative.as_posix())
        return relative.as_posix()
    return ""


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


def _batch_home(project: Path) -> Path:
    """The run's directory for batches: config, plugin, their files and Psalm's cache."""
    global _BATCH_HOME
    if _BATCH_HOME is None:
        _BATCH_HOME = Path(tempfile.mkdtemp(prefix="sca-psalm-batch-"))
        atexit.register(shutil.rmtree, _BATCH_HOME, True)
    home = _BATCH_HOME / re.sub(r"[^\w.-]+", "_", str(project)).strip("_")[-80:]
    (home / "cache").mkdir(parents=True, exist_ok=True)
    return home


def _batch_references(methods: list[str], *, binary: str, project: Path,
                      timeout_s: float) -> dict[str, list[tuple[str, int]]]:
    """References to every method from one analysis of the project; {} when the batch fails.

    Call it under `_BATCH_LOCK`: batches share one Psalm cache and one set of files.
    """
    if not methods:
        return {}
    home = _batch_home(project)
    config = _config(home / "psalm.xml", project, cache=home / "cache")
    source, result = home / "references-in.json", home / "references-out.json"
    plugin = home / "ScaReferences.php"
    result.unlink(missing_ok=True)
    source.write_text(json.dumps(methods), encoding="utf-8")
    plugin.write_text(_REFERENCES_PLUGIN % {"input": _php_string(str(source)),
                                            "output": _php_string(str(result))}, encoding="utf-8")
    _, problem = _run([binary, f"--config={config}", f"--root={project}", "--no-progress",
                       "--threads=1", f"--find-references-to={methods[0]}", f"--plugin={plugin}"],
                      home, timeout_s, f"поиск вызовов пачкой ({len(methods)} методов)")
    try:
        payload = json.loads(result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.info("psalm api: batch of %d methods gave no answer (%s); asking one by one",
                 len(methods), problem or "no output")
        return {}
    found: dict[str, list[tuple[str, int]]] = {}
    for method, rows in (payload.items() if isinstance(payload, dict) else ()):
        if not isinstance(rows, list):
            continue          # {"error": ...}: this method is asked on its own
        sites: list[tuple[str, int]] = []
        for row in rows:
            if isinstance(row, list) and len(row) == 2:
                file = _relative(str(row[0]), home, project)
                site = (file, int(row[1])) if file else None
                if site and site not in sites:
                    sites.append(site)
        found[method] = sites
    return found


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
    answer = _run_once(project, targets, binary=binary, php=php, timeout_s=timeout_s)
    for _ in range(MAX_UNREADABLE):
        if not answer.problem or not (skipped := exclude_crashed_file(project, answer.problem)):
            break
        log.warning("psalm api: %s left out — Psalm cannot read it; asking again", skipped)
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
        wanted = list(dict.fromkeys(f"{_clean_class(sig.declaring)}::{sig.function}"
                                    for sig in signatures if sig.kind != "function"))
        if len(wanted) > 1:
            with _BATCH_LOCK:
                with _REFERENCES_LOCK:
                    missing = [m for m in wanted if (str(project), m) not in _REFERENCES]
                if len(missing) > 1:
                    batch = _batch_references(missing, binary=binary, project=project, timeout_s=timeout_s)
                    with _REFERENCES_LOCK:
                        for method, sites in batch.items():
                            _REFERENCES[(str(project), method)] = sites
        for sig in signatures:
            if sig.kind == "function":
                continue
            method = f"{_clean_class(sig.declaring)}::{sig.function}"

            def find(method=method, sig=sig):
                output, problem = _run([binary, f"--config={base_config}", f"--root={project}", "--no-cache",
                                        "--no-progress", "--threads=1", f"--find-references-to={method}"],
                                       work, timeout_s, f"поиск вызовов {sig.label}")
                return ([], problem) if problem else (parse_references(output, work, project), "")

            found, problem = _references((str(project), method), find)
            if problem:
                return ApiAnswer(problem=problem, engine="psalm")
            references[sig.label] = found
            if references[sig.label]:
                answer.calls[sig.label] = [_hit(project, file, line) for file, line in references[sig.label]]

        methods = {sig.label: f"{_clean_class(sig.declaring)}::{sig.function}" for sig in signatures}
        with _TAINT_LOCK:
            todo = [sig for sig in signatures if (str(project), methods[sig.label]) not in _TAINT]
            if todo:
                # Without Psalm's cache: the stub marks different methods as sinks on
                # every run, and a cached storage could carry the previous run's sinks.
                stub_path = work / "sca-sinks.php"
                stub_path.write_text(stub(todo), encoding="utf-8")
                taint_config = _config(work / "psalm-taint.xml", project, stub_path)
                report = work / "taint.sarif"
                _, problem = _run([binary, f"--config={taint_config}", f"--root={project}", "--taint-analysis",
                                   "--no-cache", "--no-progress", "--threads=1", f"--report={report}"],
                                  work, timeout_s, "taint-анализ")
                if problem:
                    return ApiAnswer(calls=answer.calls, problem=problem, engine="psalm")
                try:
                    document = json.loads(report.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    return ApiAnswer(calls=answer.calls, problem=f"отчёт taint-анализа не прочитан: {exc}",
                                     engine="psalm")
                fresh = parse_taint(document, work, project, todo, references)
                for sig in todo:
                    _TAINT[(str(project), methods[sig.label])] = fresh.get(sig.label)
            answer.reached = {label: reached for label, method in methods.items()
                              if (reached := _TAINT.get((str(project), method))) is not None}
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
