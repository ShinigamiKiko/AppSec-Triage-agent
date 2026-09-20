"""The model investigates a dependency CVE, and CodeQL answers every question."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..prompts import registry
from . import codeql_reach

log = logging.getLogger(__name__)

SYSTEM = registry.step("codeql-agent")
TOOLS_SYSTEM = registry.step("codeql-agent-tools")

_ROUNDS = 3
_MAX_FUNCTIONS = 6
_MAX_SITES = 4
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
_CLASS_NAME = re.compile(r"^\\?[A-Za-z_$][\w$]*(\\[A-Za-z_$][\w$]*)*$")

_SCHEMA = {
    "type": "object",
    "required": ["package", "functions", "sites", "why"],
    "properties": {
        "package": {"type": "boolean"},
        "functions": {
            "type": "array", "maxItems": _MAX_FUNCTIONS, "items": {
                "type": "object", "required": ["name", "vulnerable"],
                "properties": {"name": {"type": "string"}, "class": {"type": "string"},
                               "vulnerable": {"type": "boolean"}},
            },
        },
        "sites": {
            "type": "array", "maxItems": _MAX_SITES, "items": {
                "type": "object", "required": ["file", "line"],
                "properties": {"file": {"type": "string"}, "line": {"type": "integer"}},
            },
        },
        "why": {"type": "string"},
    },
}


@dataclass(slots=True)
class Investigation:
    """What the model's own CodeQL questions established."""

    label: str = ""
    klass: str = ""
    found: object = None
    answer: object = None
    reached: codeql_reach.Reached | None = None
    requests: int = 0
    detail: str = ""
    via_tools: bool = False
    tool_calls: int = 0
    package_used: bool | None = None
    lsp_log: list[str] = field(default_factory=list)
    lsp_not_called: list[str] = field(default_factory=list)
    lsp_called: list[str] = field(default_factory=list)


def _material(advisory, symbol, package: str, engine: str = "CodeQL") -> str:
    lines = [
        f"Advisory: {advisory.advisory_id} — {advisory.summary}",
        (advisory.details or "")[:1500],
        f"Vulnerable package: {package} ({advisory.ecosystem or 'unknown ecosystem'})",
        f"Analysis engine for this project: {engine}.",
    ]
    if engine == "Psalm":
        lines.append("This is a PHP project: put the fully qualified class name in `class` "
                     "(for example Symfony\\Component\\Yaml\\Yaml), the method name in `name`, and leave "
                     "`class` empty only for a plain function. Position questions (`sites`) are not available.")
    database_symbols = [str(s) for s in (getattr(advisory, "symbols", None) or [])][:12]
    if database_symbols:
        lines.append("Vulnerable symbols the vulnerability database lists (import path, then Function or "
                     "Type.Method): " + ", ".join(database_symbols))
    if (getattr(advisory, "ecosystem", "") or "").strip().lower() in ("go", "golang"):
        lines.append("This is a Go dependency: put a function's bare name in `name` (Unmarshal) and leave "
                     "`class` empty; for a method put the receiver type in `class` (Decoder) and the method "
                     "in `name` (Decode). Never put the import path or the package name in `name`.")
    if symbol is not None and str(symbol) and getattr(symbol, "function", ""):
        lines.append(f"Vulnerable function named by the fix analysis: {symbol}")
    if symbol is not None and getattr(symbol, "what_changed", ""):
        lines.append(f"What the fix changed: {symbol.what_changed}")
    return "\n\n".join(line for line in lines if line)


_SENTENCE = re.compile(r"[^.!?\n]+[.!?]?")
_UNAFFECTED = re.compile(
    r"\b(?:un-?affected|not\s+(?:be\s+)?(?:affected|vulnerable|impacted)|is\s+safe|are\s+safe|safe\s+alternative)\b",
    re.IGNORECASE)
_CLAUSE = re.compile(r"\s*(?:[;,]|\bwhile\b|\bwhereas\b|\bbut\b|\bhowever\b)\s*", re.IGNORECASE)
_ABOUT_CALLERS = re.compile(
    r"\b(?:do(?:es)?\s+not|don't|doesn't|never|without|unless|only\s+if|only\s+when)\b", re.IGNORECASE)


def declared_unaffected(advisory, name: str) -> str:
    """The advisory's own sentence saying this function is not affected, or ""."""
    if not name:
        return ""
    text = f"{getattr(advisory, 'summary', '') or ''}\n{getattr(advisory, 'details', '') or ''}"
    mention = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
    for sentence in _SENTENCE.findall(text):
        for clause in _CLAUSE.split(sentence):
            named = mention.search(clause)
            phrase = _UNAFFECTED.search(clause)
            if named and phrase and named.start() < phrase.start() and not _ABOUT_CALLERS.search(clause):
                return " ".join(sentence.split())
    return ""


def _functions(reply: dict, asked: set[str]) -> list[tuple[str, str, bool]]:
    """(name, class, vulnerable) for each new, well-formed function the model asked about."""
    functions = []
    for item in (reply.get("functions") or [])[:_MAX_FUNCTIONS]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").split("::")[-1].split(".")[-1].strip().rstrip("()")
        klass = str(item.get("class") or "").strip()
        if not _CLASS_NAME.match(klass or "a"):
            continue
        klass = klass.lstrip("\\")
        label = f"{klass}::{name}" if klass else name
        if name and _IDENTIFIER.match(name) and label not in asked:
            asked.add(label)
            functions.append((name, klass, item.get("vulnerable") is True))
    return functions


def _sites(reply: dict, asked: set[tuple[str, int]]) -> list[tuple[str, int]]:
    sites = []
    for item in (reply.get("sites") or [])[:_MAX_SITES]:
        if not isinstance(item, dict):
            continue
        file = str(item.get("file") or "").replace("\\", "/").strip()
        line = item.get("line")
        path = PurePosixPath(file)
        if (not file or path.is_absolute() or ".." in path.parts
                or not isinstance(line, int) or line < 1 or (file, line) in asked):
            continue
        asked.add((file, line))
        sites.append((file, line))
    return sites


@dataclass(slots=True)
class _Session:
    """What both question protocols share, so the trust rules are written once."""

    advisory: object
    engine: str
    ask_functions: Callable[[list[tuple[str, str]]], object]
    ask_sites: Callable[[list[tuple[str, int]]], object]
    ask_package: Callable[[], tuple[bool | None, str, bool]] | None
    result: Investigation
    asked_functions: set[str] = field(default_factory=set)
    asked_sites: set[tuple[str, int]] = field(default_factory=set)
    package: str = ""
    package_checked: bool = False
    lsp: object = None
    code: object = None
    engine_available: bool = True
    asked_usages: set[str] = field(default_factory=set)

    def check_package(self) -> str:
        """Ask the project-level usage tool before looking for vulnerable calls."""
        if self.package_checked:
            return "Package usage was already checked."
        self.package_checked = True
        if self.ask_package is None:
            return "проверка использования пакета недоступна"
        used, detail, test_only = self.ask_package()
        self.result.package_used = used
        if used is False:
            suffix = " (только тесты)" if test_only else ""
            return f"Пакет не используется в production{suffix}: {detail}"
        if used is True:
            return f"Пакет используется: {detail}"
        return f"Использование пакета не определено: {detail}"

    def _normalise(self, reply: dict) -> dict:
        """A Go name as a model writes it, turned into the (name, class) the queries match."""
        ecosystem = (getattr(self.advisory, "ecosystem", "") or "").strip().lower()
        if ecosystem not in ("go", "golang") or not isinstance(reply, dict):
            return reply
        package = self.package.strip()
        items = []
        for item in reply.get("functions") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip().rstrip("()").lstrip("*")
            klass = str(item.get("class") or "").strip().lstrip("*").rsplit(".", 1)[-1]
            if package and name.startswith(package + "."):
                name = name[len(package) + 1:]
            if (not name or "/" in name or name == package
                    or (package and (package.endswith("." + name) or package.endswith("/" + name)))):
                continue
            if not klass and name.count(".") == 1:
                head, tail = name.split(".")
                if head[:1].isupper():
                    klass, name = head, tail
                else:
                    name = tail
            items.append({**item, "name": name, "class": klass})
        return {**reply, "functions": items}

    def functions(self, reply: dict) -> list[str] | None:
        """Ask the engine about the functions in `reply`."""
        functions = _functions(self._normalise(reply), self.asked_functions)
        if not functions:
            return None
        lines: list[str] = []
        vulnerable: set[str] = set()
        for name, klass, flag in functions:
            label = f"{klass}::{name}" if klass else name
            if not flag:
                continue
            if sentence := declared_unaffected(self.advisory, name):
                lines.append(f"- {label} is marked context, not vulnerable: the advisory says «{sentence[:200]}»")
                log.info("codeql investigation for %s: %s overruled by advisory text",
                         getattr(self.advisory, "advisory_id", "?"), label)
                continue
            vulnerable.add(label)
        pairs = [(name, klass) for name, klass, _ in functions]
        result = self.result
        result.requests += 1
        answer = self.ask_functions(pairs)
        if answer is None:
            lines.append(f"{self.engine} cannot be asked about these functions for this project.")
            return lines
        if not answer.usable:
            lines.append(f"{self.engine} did not run: {answer.problem}")
            return lines
        for name, klass in pairs:
            label = f"{klass}::{name}" if klass else name
            hits = answer.calls.get(label) or []
            reached = answer.reached.get(label)
            listed = "; ".join(f"{hit} {hit.text[:100]}" for hit in hits[:5])
            role = "" if label in vulnerable else " (context — not marked vulnerable, not evidence)"
            lines.append(f"- {label}{role}: {len(hits)} call(s)" + (f": {listed}" if listed else ""))
            if reached is not None:
                lines.append(f"  {reached.render()}")
            elif hits:
                lines.append("  no path from untrusted input to these calls")
            if (hits and label in vulnerable
                    and (result.found is None or (reached is not None and result.reached is None))):
                result.label, result.klass, result.answer = label, klass, answer
                result.found = answer.presence(label)
                if reached is not None:
                    result.reached = reached
        return lines

    def usages(self, name: str, klass: str, vulnerable: bool) -> str:
        """Ask the language server who in the project calls one package function."""
        from .lsp_tools import valid_name

        name = str(name or "").split("::")[-1].split(".")[-1].strip().rstrip("()")
        klass = str(klass or "").strip().lstrip("\\")
        label = f"{klass}::{name}" if klass else name
        if not valid_name(name) or not _CLASS_NAME.match(klass or "a"):
            return "Not run: the name is not a valid identifier."
        if label in self.asked_usages:
            return "Not run: already asked, the answer is above."
        self.asked_usages.add(label)
        note = "" if vulnerable else " (context — not marked vulnerable, not evidence)"
        if vulnerable and (sentence := declared_unaffected(self.advisory, name)):
            vulnerable = False
            note = f" (context: the advisory says «{sentence[:160]}»)"
        answer = self.lsp.usages(klass, name)
        if not answer.answered:
            line = f"LSP find_usages {label}{note}: {answer.problem}"
        elif answer.project_hits:
            listed = "; ".join(answer.project_hits[:5])
            line = (f"LSP find_usages {label}{note}: {len(answer.project_hits)} reference(s) from project "
                    f"code: {listed}")
            if vulnerable:
                self.result.lsp_called.append(f"{label}: {listed}")
        else:
            line = (f"LSP find_usages {label}{note}: 0 references from project code "
                    f"(declaration {', '.join(answer.declarations)}; the server answered)")
            if vulnerable:
                self.result.lsp_not_called.append(label)
        self.result.lsp_log.append(line)
        return line

    def code_question(self, method: str, arguments: dict) -> str:
        """One entity question to the project's language servers, logged for the report."""
        from ..lsp.code_tools import as_int
        from ..redact import redact_secrets

        code = self.code
        file = str(arguments.get("file") or "").replace("\\", "/")
        name = str(arguments.get("name") or "").strip()
        if method == "find_symbol":
            answer = code.find_symbol(arguments.get("query"))
            asked = f"{arguments.get('query')!r}"
        elif method == "find_usages":
            answer = code.find_usages(arguments.get("name"))
            asked = f"{arguments.get('name')!r}"
        elif method == "outline":
            answer, asked = code.outline(file), file
        elif method == "read_symbol":
            start, problem = code.symbol_start(file, name)
            if start is None:
                answer = problem
            else:
                path = code.resolve(file)
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[start - 1:start + 59]
                body = "\n".join(f"{start + i}: {text}" for i, text in enumerate(lines))
                answer = redact_secrets(body)[0] or ""
            asked = f"{name} @ {file}"
        else:
            line = as_int(arguments.get("line"))
            if line is None or line < 1 or not file:
                return "Not run: give a repository-relative file and a line of 1 or more."
            if method == "callers":
                answer = code.callers(file, line)
            elif method == "definition":
                answer = code.definition(file, line, name)
            else:
                answer = code.references(file, line, name)
            asked = f"{name} @ {file}:{line}" if name else f"{file}:{line}"
        # The log keeps the question and a bounded answer; code bodies stay out of it.
        shown = answer if method != "read_symbol" else f"прочитано {len(answer.splitlines())} строк"
        self.result.lsp_log.append(f"LSP lsp_{method} {asked}: {shown[:300]}")
        return answer

    def sites(self, reply: dict) -> list[str] | None:
        """Ask the engine about the positions in `reply`."""
        sites = _sites(reply, self.asked_sites)
        if not sites:
            return None
        result = self.result
        result.requests += 1
        outcome = self.ask_sites(sites)
        where = ", ".join(f"{file}:{line}" for file, line in sites)
        if isinstance(outcome, codeql_reach.Reached):
            at_vulnerable_call = result.found is not None and any(
                (hit.file, hit.line) == (outcome.file, outcome.line) for hit in result.found.hits)
            if at_vulnerable_call:
                result.reached = result.reached or outcome
            return [outcome.render()]
        if outcome is False:
            return [f"CodeQL: no path from untrusted input to {where}."]
        if isinstance(outcome, str):
            return [outcome]
        return [f"CodeQL could not evaluate {where} (no database, or not a call in it)."]


TOOLS = [
    {"type": "function", "function": {
        "name": "check_package",
        "description": "Check whether the vulnerable dependency is used by production code. Call this first.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "find_calls",
        "description": ("Find every call this project makes to one function of the vulnerable package, "
                        "resolved by the analyser through the package's exports, and whether untrusted "
                        "input reaches its arguments — with the path. One function per call."),
        "parameters": {"type": "object", "required": ["name", "vulnerable"], "properties": {
            "name": {"type": "string", "description": "Function or method name, without parentheses."},
            "class": {"type": "string",
                      "description": "Class of a method — fully qualified for PHP. Empty for a plain function."},
            "vulnerable": {"type": "boolean",
                           "description": "True only if the advisory says this function is affected."},
        }},
    }},
    {"type": "function", "function": {
        "name": "check_call_site",
        "description": "Whether untrusted input reaches the call at this repository-relative file and 1-based line.",
        "parameters": {"type": "object", "required": ["file", "line"], "properties": {
            "file": {"type": "string", "description": "Repository-relative path."},
            "line": {"type": "integer", "description": "1-based line of the call."},
        }},
    }},
]

LSP_TOOLS = [
    {"type": "function", "function": {
        "name": "find_usages",
        "description": ("Language server: every reference from this project's code to one function or method "
                        "of the vulnerable package, found from its declaration in the installed package. "
                        "Tells a real call of the library apart from a same-named function of the project."),
        "parameters": {"type": "object", "required": ["name", "vulnerable"], "properties": {
            "name": {"type": "string", "description": "Function or method name, without parentheses."},
            "class": {"type": "string",
                      "description": ("Class or receiver type of a method — fully qualified for PHP. "
                                      "Empty for a plain function.")},
            "vulnerable": {"type": "boolean",
                           "description": ("True only if the advisory says this function is affected, or it "
                                           "is the public entry point an application calls to reach the flaw.")},
        }},
    }},
]


def _function_tool(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "required": required, "properties": properties}}}

_MAX_TOOL_CALLS = 8


def _flag(value: object) -> bool:
    """`vulnerable` as the model meant it: a local model sometimes sends "true"."""
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _line(value: object) -> object:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _run_tool(session: _Session, name: str, arguments: dict, offered: set[str]) -> str:
    """Execute one tool call and return what the model is shown."""
    if name not in offered:
        return f"Unknown tool {name!r}. Available: {', '.join(sorted(offered))}."
    if name == "check_package":
        return session.check_package()
    if session.ask_package is not None and not session.package_checked:
        return "Not run: call check_package first."
    if name == "find_usages":
        return session.usages(arguments.get("name"), arguments.get("class") or "",
                              _flag(arguments.get("vulnerable")))
    if name.startswith("lsp_") and session.code is not None:
        return session.code_question(name[4:], arguments)
    if name == "find_calls":
        lines = session.functions({"functions": [{
            "name": arguments.get("name"), "class": arguments.get("class") or "",
            "vulnerable": _flag(arguments.get("vulnerable"))}]})
        if lines is None:
            return ("Not run: the name is not a valid identifier, or this function was already asked "
                    "and its answer is above.")
        return "\n".join(lines)
    lines = session.sites({"sites": [{"file": arguments.get("file"), "line": _line(arguments.get("line"))}]})
    if lines is None:
        return ("Not run: the position must be a repository-relative file and a line of 1 or more, "
                "not asked before.")
    return "\n".join(lines)


def _investigate_with_tools(client, session: _Session, material: str, rounds: int,
                            parallel_llm: int = 2) -> None:
    """The model calls the analyser itself and reacts to each answer."""
    from ..llm.tools import run_tool_loop
    
    result = session.result
    advisory_id = getattr(session.advisory, "advisory_id", "?")
    
    # Psalm answers by type, not by position, so it is offered no position tool.
    tools = [TOOLS[0]]
    if session.engine_available:
        tools += TOOLS[1:] if session.engine == "CodeQL" else [TOOLS[1]]
    if session.lsp is not None:
        tools += LSP_TOOLS
    if session.code is not None:
        from ..lsp.code_tools import function_tools

        tools += function_tools(_function_tool)
    offered = {tool["function"]["name"] for tool in tools}
    
    def make_handler(call_name: str):
        def handler(arguments: dict) -> str:
            if result.tool_calls >= _MAX_TOOL_CALLS:
                return "Not run: the limit of questions to the analyser is reached."
            result.tool_calls += 1
            log.info("[%s] executing tool: %s(%s)", advisory_id, call_name,
                     json.dumps(arguments, ensure_ascii=False)[:300])
            content = _run_tool(session, call_name, arguments, offered)
            if call_name == "check_package" and result.package_used is False:
                # Signal early exit by raising
                raise StopIteration("package not used in production")
            return content
        return handler
    
    handlers = {tool["function"]["name"]: make_handler(tool["function"]["name"]) for tool in tools}
    
    try:
        loop = run_tool_loop(
            client=client,
            system=TOOLS_SYSTEM,
            user=material,
            tools=tools,
            handlers=handlers,
            max_calls=_MAX_TOOL_CALLS,
            max_turns=max(1, rounds) * 3,
            parallel_limit=parallel_llm,
            finding_id=advisory_id,
        )
        if loop.error:
            # Check if it's a fallback-worthy error
            if "tool" in loop.error.lower() or "function" in loop.error.lower():
                log.info("[%s] native tools rejected, falling back to JSON protocol", advisory_id)
                _investigate_with_json(client, session, material, rounds)
                return
            result.detail = loop.error
        if result.tool_calls >= _MAX_TOOL_CALLS:
            result.detail = result.detail or f"достигнут лимит в {_MAX_TOOL_CALLS} вопросов к {session.engine}"
    except StopIteration as early_exit:
        log.info("[%s] investigation stopped early: %s", advisory_id, early_exit)
        return


def _investigate_with_json(client, session: _Session, material: str, rounds: int) -> None:
    """The model names its questions in a JSON reply; answers return next round."""
    result = session.result
    for round_no in range(1, rounds + 1):
        left = getattr(client, "budget_left_usd", None)
        if isinstance(left, (int, float)) and not isinstance(left, bool) and left <= 0:
            result.detail = "бюджет прогона исчерпан"
            break
        try:
            reply = json.loads(client.complete(SYSTEM, material, json_schema=_SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - the chain's own search still runs
            log.warning("codeql investigation round %d failed for %s: %s",
                        round_no, getattr(session.advisory, "advisory_id", "?"), exc)
            result.detail = f"раунд {round_no} не выполнен: {exc}"
            break
        if not isinstance(reply, dict):
            break
        package_was_checked = session.package_checked
        if reply.get("package") is not None:
            session.check_package()
            if session.result.package_used is False:
                break
        functions = session.functions(reply)
        sites = session.sites(reply)
        # If package check was the only thing requested, continue to next round
        if (functions is None and sites is None
                and (reply.get("package") is None or package_was_checked)):
            break
        additions = [f"=== {session.engine.upper()} ANSWERS, ROUND {round_no} ===",
                     *(functions or []), *(sites or [])]
        material = f"{material}\n\n" + "\n".join(additions)


def investigate(
    client, advisory, symbol, package: str, *,
    ask_functions: Callable[[list[tuple[str, str]]], object],
    ask_sites: Callable[[list[tuple[str, int]]], object],
    ask_package: Callable[[], tuple[bool | None, str, bool]] | None = None,
    rounds: int = _ROUNDS,
    engine: str = "CodeQL",
    api_hint: str = "",
    lsp_tools=None,
    engine_available: bool = True,
    code_tools=None,
    parallel_llm: int = 2,
) -> Investigation:
    """Let the model question the analysis engine about this CVE; return what it established."""
    result = Investigation()
    if client is None:
        result.detail = f"модель не подключена — {engine} моделью не опрашивался"
        return result

    material = _material(advisory, symbol, package, engine)
    if api_hint:
        material = f"{material}\n\n{api_hint}"
    lsp = lsp_tools if lsp_tools is not None and lsp_tools.available else None
    code = code_tools if code_tools is not None and code_tools.available() else None
    if lsp is not None or code is not None:
        material = (f"{material}\n\nLanguage servers indexed this project and are available as tools: "
                    "find_usages for callers of a package function, and lsp_* to find, read and follow any "
                    "declaration in the project's code.")
    session = _Session(advisory, engine, ask_functions, ask_sites, ask_package, result, package=package,
                       lsp=lsp, engine_available=engine_available, code=code)
    if getattr(client, "supports_tools", False) is True and callable(getattr(client, "chat_tools", None)):
        result.via_tools = True
        _investigate_with_tools(client, session, material, rounds, parallel_llm)
    else:
        if lsp is not None:
            result.lsp_log.append("LSP: провайдер не поддерживает tool calling — языковой сервер моделью не опрашивался")
        _investigate_with_json(client, session, material, rounds)

    log.info("codeql investigation for %s via %s: %d request(s), found=%s, reached=%s", advisory.advisory_id,
             "tool calls" if result.via_tools else "json", result.requests, result.label or "-",
             bool(result.reached))
    return result
