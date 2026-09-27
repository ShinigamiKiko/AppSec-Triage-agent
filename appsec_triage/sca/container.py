"""Which concrete class sits behind an interface, according to the container."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

try:  # pragma: no cover - environment dependent
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

log = logging.getLogger(__name__)

_CONFIG_DIRS = ("config", "app/config")
_MAX_FILES = 400
_LOOKS_LIKE_CLASS = re.compile(r"^[A-Za-z_][\w]*(\\[A-Za-z_][\w]*)+$")


@dataclass(slots=True)
class Wiring:
    """What the configuration says, with nothing inferred."""

    classes: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    decorates: dict[str, str] = field(default_factory=dict)
    arguments: dict[str, dict[str, str]] = field(default_factory=dict)
    files_read: list[str] = field(default_factory=list)
    problem: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.classes or self.aliases or self.decorates)

    def resolve(self, name: str, depth: int = 6) -> str:
        """Follow aliases and `class:` to a concrete class name, or return ""."""
        seen: set[str] = set()
        current = name
        for _ in range(depth):
            if not current or current in seen:
                break
            seen.add(current)
            if current in self.aliases:
                current = self.aliases[current]
                continue
            if current in self.classes:
                target = self.classes[current]
                if target == current:
                    return target
                current = target
                continue
            break
        return current if _LOOKS_LIKE_CLASS.match(current or "") else ""

    def decorated_class(self, decorator: str, argument: str = "") -> str:
        """The class behind a decorator's inner service, if configuration says."""
        target = ""
        if argument:
            declared = (self.arguments.get(decorator) or {}).get(argument.lstrip("$"), "")
            if declared and declared != ".inner":
                target = declared
        if not target:
            target = self.decorates.get(decorator, "")
        return self.resolve(target) if target else ""


def _short(name: str) -> str:
    return name.rsplit("\\", 1)[-1]


def _service_id(value: str) -> str:
    return value.lstrip("@?").strip()


if yaml is not None:  # pragma: no branch - trivial

    class _SymfonyLoader(yaml.SafeLoader):
        """A safe loader that survives Symfony's own tags."""


    def _ignore_tag(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _SymfonyLoader.add_multi_constructor("!", _ignore_tag)


# Symfony reads an unquoted value inside `{ ... }` or `[ ... ]` up to the next `,` or
# closing bracket, so `{ path: ^/v2/x/([a-z\d]+), roles: ROLE_USER }` is fine to it.
# YAML proper ends the value at the `[`, and PyYAML rejects the whole file — over an
# access_control regex, a common line of security.yaml. The line PyYAML stops at is
# rewritten the way Symfony reads it (as JSON, which is YAML too) and read again.
_FLOW_START = re.compile(r"""^(\s*(?:-\s+)*(?:[^\s#'"{\[][^#]*?:\s+)?)[\[{]""")
MAX_REWRITES = 50


def parse_yaml(text: str):
    """A Symfony configuration file as Symfony reads it; raises yaml.YAMLError."""
    lines = text.split("\n")
    for _ in range(MAX_REWRITES):
        try:
            return yaml.load("\n".join(lines), Loader=_SymfonyLoader)
        except yaml.MarkedYAMLError as exc:
            mark = exc.problem_mark or exc.context_mark
            if mark is None or not 0 <= mark.line < len(lines):
                raise
            fixed = _symfony_inline(lines[mark.line])
            if fixed is None or fixed == lines[mark.line]:
                raise
            lines[mark.line] = fixed
    return yaml.load("\n".join(lines), Loader=_SymfonyLoader)


def _symfony_inline(line: str) -> str | None:
    """The line with its inline collection read by Symfony's rules; None when it has none."""
    match = _FLOW_START.match(line)
    if not match:
        return None
    start = match.end(1)
    try:
        value, end = _inline_value(line, start, "")
    except (ValueError, IndexError):
        return None
    return line[:start] + json.dumps(value, ensure_ascii=False, default=str) + line[end:]


def _inline_value(text: str, i: int, stops: str):
    while text[i] == " ":
        i += 1
    if text[i] == "[":
        items: list = []
        i += 1
        while True:
            while text[i] in " ,":
                i += 1
            if text[i] == "]":
                return items, i + 1
            item, i = _inline_value(text, i, ",]")
            items.append(item)
            while text[i] == " ":
                i += 1
            if text[i] not in ",]":
                raise ValueError(text[i:])
    if text[i] == "{":
        mapping: dict = {}
        i += 1
        while True:
            while text[i] in " ,":
                i += 1
            if text[i] == "}":
                return mapping, i + 1
            if text[i] in "\"'":
                end = _quoted_end(text, i)
                key = _scalar(text[i:end])
                i = end
                while text[i] == " ":
                    i += 1
            else:
                end = text.index(":", i)
                key = text[i:end].strip()
                i = end
            if text[i] != ":":
                raise ValueError(text[i:])
            mapping[str(key)], i = _inline_value(text, i + 1, ",}")
            while text[i] == " ":
                i += 1
            if text[i] not in ",}":
                raise ValueError(text[i:])
    if text[i] in "\"'":
        end = _quoted_end(text, i)
        return _scalar(text[i:end]), end
    end = i
    while end < len(text) and text[end] not in stops:
        end += 1
    if stops and end >= len(text):
        raise ValueError("unclosed")
    return _scalar(text[i:end].strip()), end


def _quoted_end(text: str, i: int) -> int:
    quote, j = text[i], i + 1
    while j < len(text):
        if quote == '"' and text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            if quote == "'" and text[j + 1:j + 2] == "'":
                j += 2
                continue
            return j + 1
        j += 1
    raise ValueError("unclosed quote")


def _scalar(raw: str):
    if not raw:
        return None
    try:
        value = yaml.load(raw, Loader=_SymfonyLoader)
    except yaml.YAMLError:
        return raw
    return raw if isinstance(value, (dict, list)) else value


def _read(path: Path) -> dict | None:
    if yaml is None:
        return None
    try:
        loaded = parse_yaml(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        log.warning("configuration file %s could not be parsed: %s", path, exc)
        return None
    return loaded if isinstance(loaded, dict) else None


def load(root: Path | str) -> Wiring:
    """Read a project's service configuration."""
    root = Path(root)
    wiring = Wiring()
    if yaml is None:
        wiring.problem = "pyyaml не установлен — конфигурация контейнера не читается"
        return wiring

    files: list[Path] = []
    for directory in _CONFIG_DIRS:
        base = root / directory
        if base.is_dir():
            files.extend(sorted(p for p in base.rglob("*.y*ml") if p.is_file()))
    if not files:
        wiring.problem = f"в {root} нет каталога config — контейнер не описан"
        return wiring

    for path in files[:_MAX_FILES]:
        document = _read(path)
        if not document:
            continue
        services = document.get("services")
        if not isinstance(services, dict):
            continue
        wiring.files_read.append(str(path.relative_to(root)))

        for key, value in services.items():
            if not isinstance(key, str) or key.startswith("_"):
                continue
            if isinstance(value, str):
                wiring.aliases[key] = _service_id(value)
                continue
            if not isinstance(value, dict):
                continue
            if isinstance(value.get("class"), str):
                wiring.classes[key] = value["class"]
            if isinstance(value.get("alias"), str):
                wiring.aliases[key] = _service_id(value["alias"])
            if isinstance(value.get("decorates"), str):
                wiring.decorates[key] = _service_id(value["decorates"])
            arguments = value.get("arguments")
            if isinstance(arguments, dict):
                named = {
                    str(name).lstrip("$"): _service_id(str(target))
                    for name, target in arguments.items()
                    if isinstance(target, str) and target.startswith("@")
                }
                if named:
                    wiring.arguments[key] = named

    for key in (*wiring.decorates, *wiring.aliases.values(), *wiring.aliases):
        if key not in wiring.classes and _LOOKS_LIKE_CLASS.match(key):
            wiring.classes[key] = key

    if not wiring.usable:
        wiring.problem = (f"прочитано {len(wiring.files_read)} файл(ов) конфигурации, "
                          "определений сервисов в них нет")
    return wiring


def property_type(text: str, prop: str) -> str:
    """The declared type of `$prop` in this file: typed property or constructor."""
    name = re.escape(prop.lstrip("$"))
    patterns = (
        rf"(?:private|protected|public|readonly)\s+(?:readonly\s+)?\??([\w\\]+)\s+\${name}\b",
        rf"function\s+__construct\s*\([^)]*?\??([\w\\]+)\s+\${name}\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            found = match.group(1)
            if found.lower() not in ("array", "string", "int", "float", "bool",
                                     "callable", "iterable", "mixed", "object",
                                     "static", "self"):
                return found
    return ""


def class_of_file(text: str) -> str:
    """The fully qualified class this file declares, for keying configuration."""
    namespace = re.search(r"^\s*namespace\s+([\w\\]+)\s*;", text, re.MULTILINE)
    declared = re.search(r"^\s*(?:final\s+|abstract\s+)*class\s+(\w+)", text, re.MULTILINE)
    if not declared:
        return ""
    return f"{namespace.group(1)}\\{declared.group(1)}" if namespace else declared.group(1)


@dataclass(slots=True)
class ReceiverType:
    klass: str = ""
    via: str = ""
    detail: str = ""


def receiver_class(wiring: Wiring, file_text: str, receiver: str) -> ReceiverType:
    """The concrete class held by `$this->something`, per the configuration."""
    prop = receiver.strip()
    if not prop.startswith("$this->"):
        return ReceiverType(detail=f"получатель {receiver} — не свойство объекта")
    prop = prop[len("$this->"):]

    declared = property_type(file_text, prop)
    if not declared:
        return ReceiverType(detail=f"тип свойства ${prop} не объявлен в этом файле")

    owner = class_of_file(file_text)
    if owner:
        concrete = wiring.decorated_class(owner, prop)
        if concrete:
            return ReceiverType(_short(concrete), f"decorates у {_short(owner)}",
                                f"${prop} — декорируемый сервис {concrete}")
        target = wiring.decorates.get(owner, "")
        if target:
            return ReceiverType(
                detail=(f"${prop} — декорируемый сервис '{target}', его класс не описан "
                        f"в config/ (объявлен бандлом); проверить: "
                        f"bin/console debug:container {target}"))

    concrete = wiring.resolve(declared)
    if concrete and concrete != declared:
        return ReceiverType(_short(concrete), "алиас в services.yaml",
                            f"{declared} -> {concrete}")
    return ReceiverType(detail=(f"${prop} объявлен как {_short(declared)}, "
                                "и конфигурация не называет реализацию"))
