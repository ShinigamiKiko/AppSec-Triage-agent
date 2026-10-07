"""What a PHP application runs without any of its own code calling it.

A framework hands control to a package from bootstrap code, configuration and
files it generates into `vendor/`, which every search for "does the project call
this" skips by design. A closure that rests on "no call from the project" is wrong
for such a package, whatever the engine answered. What counts here:

- `public/index.php` requiring `vendor/autoload_runtime.php` starts symfony/runtime;
- a bundle enabled for production in `config/bundles.php` — the kernel boots it, and
  its event subscribers, controllers and Twig extensions run on their own;
  (a bundle whose routes `config/routes*.yaml` imports is one of these: routes of a
  bundle the kernel does not boot do not load);
- a file in `vendor/composer/autoload_files.php` is included on every request, but
  what it runs is the functions it defines, not the package's classes: it counts only
  for a flaw in a plain function (see `functions_loaded`);
- an authenticator configured in `security.yaml` — it runs on every request of its
  firewall (`form_login_ldap` brings symfony/ldap in as well).

A bundle maps to its package through `vendor/composer/installed.json`, so bundles
are recognised only when the dependencies are installed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# The project's own entry files: front controllers and the console.
_ENTRY_GLOBS = ("public/*.php", "web/*.php", "index.php", "bin/console", "bin/*.php")
_MAX_BYTES = 400_000

# (package, what in an entry file hands control to it)
_BOOTSTRAPS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("symfony/runtime", re.compile(r"""['"][^'"\n]*autoload_runtime\.php['"]""")),
)

_BUNDLE = re.compile(r"""^\s*\\?(?P<cls>[A-Za-z_][\w\\]*)::class\s*=>\s*\[(?P<envs>[^\]]*)\]""", re.M)
_AUTOLOAD_FILE = re.compile(r"""\$vendorDir\s*\.\s*'/(?P<package>[^/']+/[^/']+)/""")

# security.yaml firewall keys -> the packages whose code they run on every request.
_SECURITY = "symfony/security-http"
_AUTHENTICATORS: dict[str, tuple[str, ...]] = {
    "form_login_ldap": (_SECURITY, "symfony/ldap"),
    "json_login_ldap": (_SECURITY, "symfony/ldap"),
    "http_basic_ldap": (_SECURITY, "symfony/ldap"),
    **{key: (_SECURITY,) for key in ("form_login", "json_login", "http_basic", "remember_me", "login_link",
                                      "access_token", "x509", "remote_user", "custom_authenticators",
                                      "login_throttling")},
}
_SECURITY_KEY = re.compile(r"^\s+(?P<key>" + "|".join(sorted(_AUTHENTICATORS, key=len, reverse=True)) + r"):",
                           re.M)


def _read(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _line(root: Path, path: Path, text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    code = text[start:end if end >= 0 else len(text)].strip()
    return f"{path.relative_to(root).as_posix()}:{text.count(chr(10), 0, offset) + 1}: {code}"


def _namespaces(root: Path) -> list[tuple[str, str]]:
    """(namespace prefix, package), longest first, from the installed packages' autoload."""
    data = _read(root / "vendor" / "composer" / "installed.json")
    if not data:
        return []
    try:
        parsed = json.loads(data)
    except ValueError:
        return []
    packages = parsed.get("packages", []) if isinstance(parsed, dict) else parsed
    out: list[tuple[str, str]] = []
    for package in packages if isinstance(packages, list) else []:
        name = str(package.get("name") or "").lower()
        autoload = package.get("autoload") or {}
        for kind in ("psr-4", "psr-0"):
            for prefix in (autoload.get(kind) or {}):
                if prefix and name:
                    out.append((str(prefix).strip("\\") + "\\", name))
    return sorted(out, key=lambda item: -len(item[0]))


def _package_of(cls: str, namespaces: list[tuple[str, str]]) -> str:
    cls = cls.strip("\\") + "\\"
    return next((name for prefix, name in namespaces if cls.startswith(prefix)), "")


def _production_bundle(envs: str) -> bool:
    flags = dict(re.findall(r"""['"](\w+)['"]\s*=>\s*(true|false)""", envs))
    return flags.get("all") == "true" or flags.get("prod") == "true"


def framework_invoked(root: Path | str) -> dict[str, str]:
    """package -> `file:line: code` of the line that has the framework start it."""
    root = Path(root)
    found: dict[str, str] = {}

    def add(package: str, evidence: str) -> None:
        if package and package not in found:
            found[package] = evidence

    for pattern in _ENTRY_GLOBS:
        for path in sorted(root.glob(pattern)):
            text = _read(path)
            for package, marker in _BOOTSTRAPS:
                if match := marker.search(text):
                    add(package, _line(root, path, text, match.start()))

    namespaces = _namespaces(root)
    bundles_path = root / "config" / "bundles.php"
    text = _read(bundles_path)
    for match in _BUNDLE.finditer(text):
        package = _package_of(match.group("cls"), namespaces)
        if package and _production_bundle(match.group("envs")):
            add(package, _line(root, bundles_path, text, match.start("cls")))

    for path in sorted([*root.glob("config/packages/security.yaml"), *root.glob("config/packages/prod/security.yaml")]):
        text = _read(path)
        for match in _SECURITY_KEY.finditer(text):
            for package in _AUTHENTICATORS[match.group("key")]:
                add(package, _line(root, path, text, match.start("key")))
    return found


def functions_loaded(root: Path | str) -> dict[str, str]:
    """package -> the `autoload_files.php` line that includes its functions on every request.

    Only a flaw in a plain function is reached this way: the file defines functions
    (Guzzle's `describe_type`, a polyfill), it does not run the package's classes.
    """
    root = Path(root)
    autoload_files = root / "vendor" / "composer" / "autoload_files.php"
    text = _read(autoload_files)
    found: dict[str, str] = {}
    for match in _AUTOLOAD_FILE.finditer(text):
        found.setdefault(match.group("package").lower(), _line(root, autoload_files, text, match.start()))
    return found
