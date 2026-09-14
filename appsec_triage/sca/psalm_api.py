"""Psalm answers the dependency questions about a vulnerable PHP method.

PHP has no CodeQL, and a text search for `parse(` cannot tell
`Symfony\\Component\\Yaml\\Yaml::parse` from a project's own `DateParser::parse`.
Measured on seeded projects: every PHP case came back "called, receiver class not
confirmed", with no dataflow at all, and the verdict fell to policy. Psalm infers
types, so it can answer both questions CodeQL answers for JavaScript:

- **Where is the method called?** `psalm --find-references-to=Class::method`
  lists call sites resolved by type — a call through `$this->parser` counts, a
  same-named method of another class does not.
- **Does untrusted input reach it?** A stub declares the method's parameters as
  taint sinks and a taint run reports the path from `$_GET`/`$_POST` into them.

Two measured constraints shape the taint run. Psalm ignores custom sink kinds, so
the stub uses the built-in `eval` kind — and Psalm reports its own sinks too (an
`echo` of request data is XSS), so only `TaintedEval` results whose sink line
calls the named method are kept. The stub signature must match the real method,
so it is read with Reflection through the project's own `vendor/autoload.php`,
the same autoloader Psalm itself runs.

Answers use `codeql_api.ApiAnswer`, so the chain and the model's investigation
treat both engines alike: a call or a path found is a fact, a miss closes nothing.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
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
    """Fully qualified classes of the installed `package` that declare each method name.

    A fix diff names the method — `parse`, `parseBlock` — never its class, and
    PHP gives a bare name no meaning: Psalm cannot resolve it and a text search
    matches any class's `parse`. Measured on a seeded project, a bare `parse`
    matched `DateParser::parse` and reopened a closed finding. Reading which
    classes of the installed package declare the method turns the name back into
    something both Psalm and the class-bound text search can check.
    """
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


def _relative(path: str, base: Path, project: Path) -> str | None:
    """A Psalm path — relative to its working directory — as a path inside the project."""
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
    """The last line (1-based) of the call to `function` that begins on line `start`.

    Parentheses are counted outside string literals; a call that cannot be read
    as starting on that line ends where it starts.
    """
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
    """(method, line the call starts on) for a sink Psalm reported inside one of our calls.

    Psalm places the sink on the argument, and an argument written on its own
    line is below the line the call starts on: measured, `Yaml::parse(\\n $document\\n)`
    reported the sink one line down, the line did not contain `parse(`, and a real
    input path was dropped as not ours. So the sink counts when it lies inside the
    span of a call Psalm resolved to the method; a sink line that itself calls the
    method is the fallback for methods without resolved references.
    """
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


def _config(path: Path, project: Path, stub_path: Path | None = None) -> Path:
    autoload = project / "vendor" / "autoload.php"
    vendor = project / "vendor"
    parts = [
        '<?xml version="1.0"?>',
        '<psalm xmlns="https://getpsalm.org/schema/config" errorLevel="8" findUnusedCode="false"'
        + (f" autoloader={quoteattr(str(autoload))}" if autoload.is_file() else "") + ">",
        f"  <projectFiles><directory name={quoteattr(str(project))} />"
        + (f"<ignoreFiles><directory name={quoteattr(str(vendor))} /></ignoreFiles>" if vendor.is_dir() else "")
        + "</projectFiles>",
    ]
    if stub_path is not None:
        parts.append(f"  <stubs><file name={quoteattr(str(stub_path))} /></stubs>")
    parts.append("</psalm>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path


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
    return proc.stdout + "\n" + proc.stderr, ""


def run(project_root: Path | str, targets: list[Target], *, binary: str = "psalm", php: str = "php",
        timeout_s: float = _TIMEOUT_S) -> ApiAnswer:
    """Find the calls of these PHP methods and the paths from user input into them."""
    project = Path(project_root).resolve()
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
        for sig in signatures:
            if sig.kind == "function":
                continue
            output, problem = _run([binary, f"--config={base_config}", f"--root={project}", "--no-cache",
                                    "--no-progress", "--threads=1",
                                    f"--find-references-to={_clean_class(sig.declaring)}::{sig.function}"],
                                   work, timeout_s, f"поиск вызовов {sig.label}")
            if problem:
                return ApiAnswer(problem=problem, engine="psalm")
            references[sig.label] = parse_references(output, work, project)
            if references[sig.label]:
                answer.calls[sig.label] = [_hit(project, file, line) for file, line in references[sig.label]]

        stub_path = work / "sca-sinks.php"
        stub_path.write_text(stub(signatures), encoding="utf-8")
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
            return ApiAnswer(calls=answer.calls, problem=f"отчёт taint-анализа не прочитан: {exc}", engine="psalm")
        answer.reached = parse_taint(document, work, project, signatures, references)
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
