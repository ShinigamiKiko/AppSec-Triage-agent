"""Which concrete class sits behind an interface, according to the container.

A language server cannot answer this, and on measurement it mostly did not try:
asked at five call positions in a project with its dependencies installed, it
returned nothing for three and pointed at the calling file for one. The reason
is not a defect in phpactor — the answer genuinely is not in the source. In a
Symfony application the wiring lives in configuration:

    App\\Service\\ChatBotServiceInterface:
        class: App\\Service\\ChatBotService

    App\\Security\\AtsTokenAuthenticatorDecorator:
        decorates: 'Ats.security.authenticator'
        arguments:
            $decorated: '@.inner'

That is an exact statement, not an inference: `$this->decorated` in the
decorator holds whatever `Ats.security.authenticator` is. Reading it turns a
call through an interface into a call on a named class.

What is deliberately not done here is guessing. A service id that no
configuration file defines resolves to nothing and says so — many are declared
by bundles inside `vendor/`, and a repository without one cannot know them.
"""

from __future__ import annotations

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
        """The class behind a decorator's inner service, if configuration says.

        `$decorated: '@.inner'` names no service of its own — `.inner` *is* the
        decorated one — so the answer comes from the `decorates` key.
        """
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
        """A safe loader that survives Symfony's own tags.

        `!php/const`, `!tagged_iterator`, `!service` and friends are not YAML,
        and `safe_load` refuses the whole document over one of them. Refusing
        the document loses every service definition in it — measured: zero
        configuration files read on a project with a fully wired container.
        The tag's *value* is kept, which is all this needs; the tag itself never
        names a class.
        """


    def _ignore_tag(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _SymfonyLoader.add_multi_constructor("!", _ignore_tag)


def _read(path: Path) -> dict | None:
    if yaml is None:
        return None
    try:
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=_SymfonyLoader)
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
    """The declared type of `$prop` in this file: typed property or constructor.

    Both spellings occur in the same codebase and neither is optional to
    support: `private AuthenticatorInterface $decorated;` was measured next to
    promoted constructor properties in the same project.
    """
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
