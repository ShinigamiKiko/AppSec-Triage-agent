"""Calls that read the request themselves, where "no input reaches it" proves nothing.

`ctx.BodyParser(&req)` takes no user data in: it pulls the body out of the request and
writes the parsed result into its argument. A dataflow question about its arguments —
does user input reach them? — is answered "no" for every such call, however directly the
body then flows into the vulnerable function. That "no" must not close a finding.
"""

from __future__ import annotations

import re
from pathlib import Path

_CALL = re.compile(
    r"\.(?:BodyParser|QueryParser|ParamsParser|ReqHeaderParser|CookieParser"
    r"|ShouldBind\w*|MustBindWith|Bind(?:JSON|XML|YAML|TOML|Query|Header|Uri|With)?"
    r"|PostBody|ParseForm|ParseMultipartForm|PostFormValue|FormValue|FormFile|MultipartForm)\s*\("
    r"|NewDecoder\s*\([^)]*\.Body\b"
    r"|ReadAll\s*\([^)]*\.Body\b"
)

_FRAME = re.compile(
    r"\*?(?i:ctx|context|defaultctx|bind|binder|defaultbinder|request|requestctx|defaultreq)"
    r"\.(?:BodyParser|QueryParser|ParamsParser|ReqHeaderParser|CookieParser|ShouldBind\w*|MustBindWith"
    r"|Bind\w*|Body|JSON|XML|Form|Query|Header|Cookie|URI|All|Custom|MsgPack|CBOR"
    r"|PostBody|ParseForm|ParseMultipartForm|PostFormValue|FormValue|FormFile|MultipartForm)$"
)

_VENDORED = {"vendor", "node_modules", "third_party"}


def in_frames(frames) -> list[str]:
    """Call-graph frames that are request readers."""
    return [frame for frame in frames or () if _FRAME.search(str(frame))]


def in_lines(root: Path | str, positions) -> list[str]:
    """`file:line: code` of the project's own positions whose call reads the request."""
    root = Path(root)
    found: list[str] = []
    for filename, line in positions or ():
        if not filename or not isinstance(line, int) or line < 1:
            continue
        path = Path(str(filename).replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or _VENDORED & set(path.parts):
            continue
        try:
            text = (root / path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if line <= len(text) and _CALL.search(text[line - 1]):
            found.append(f"{path.as_posix()}:{line}: {text[line - 1].strip()[:160]}")
    return found


def on_path(reachability, root: Path | str) -> list[str]:
    """Every request reader a traced path runs through: its project lines, then its frames."""
    positions = list(getattr(reachability, "sites", None) or [])
    frames = [frame for path in (getattr(reachability, "paths", None) or [getattr(reachability, "trace", None) or []])
              for frame in path]
    readers = in_lines(root, positions)
    readers += [f"{frame} (в графе вызовов)" for frame in dict.fromkeys(in_frames(frames))]
    return readers


def explain(readers: list[str]) -> str:
    """The note the model reads next to the call sites."""
    return ("=== НА ПУТИ ЕСТЬ ВЫЗОВ, КОТОРЫЙ САМ ЧИТАЕТ ЗАПРОС ===\n"
            + "\n".join(readers[:6])
            + "\nТакой вызов сам достаёт данные из запроса — тело, параметры, форму — и записывает "
              "их в свой аргумент. Анализатор потока проверяет, доходят ли данные пользователя до "
              "аргументов вызова, а здесь аргумент только принимает результат, поэтому ответ «пути "
              "от пользовательского ввода нет» для такого вызова ничего не доказывает. Решайте по "
              "коду: какой декодер выберет этот вызов и чем пользователь может на это повлиять.")
