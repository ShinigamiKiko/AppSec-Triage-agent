"""Declarations and visibility in every language the bridge has to cross.

The failure mode is silent and it closes findings. An unrecognised declaration
produces no caller, which looks exactly like a library that never touches the
flaw — and "the parent never calls it" is the one bridge outcome allowed to
close. So each language is checked for both halves: that the declaration is
found at all, and that what is reachable from outside is judged the way that
language decides it.
"""

from __future__ import annotations

from appsec_triage.sca.bridge import find_bridge
from appsec_triage.sca.declarations import declarations, enclosing, language_of


def _names(path, text):
    return [(str(d), d.visibility) for d in declarations(path, text)]


def test_php_visibility_comes_from_the_keyword():
    text = ("<?php\nclass Mailer {\n"
            "  public function send($a) {}\n"
            "  private function check($a) {}\n"
            "  function legacy($a) {}\n}\n")
    assert _names("src/M.php", text) == [
        ("Mailer::send", "public"),
        ("Mailer::check", "private"),
        ("Mailer::legacy", "public"),
    ]


def test_javascript_visibility_is_what_the_module_exports():
    text = ("function helper(a) { return a; }\n"
            "export function request(u) { return helper(u); }\n"
            "const mergeConfig = (a, b) => a;\n"
            "module.exports.mergeConfig = mergeConfig;\n")
    found = dict(_names("lib/http.js", text))
    assert found["helper"] == "private", "неэкспортированное не публично"
    assert found["request"] == "public"
    assert found["mergeConfig"] == "public"


def test_typescript_keeps_its_visibility_keyword_and_hash_privates():
    text = ("export class Client {\n"
            "  public request(u: string) { return this.#send(u); }\n"
            "  #send(u: string) { return u; }\n"
            "  private retry(u: string) { return u; }\n}\n")
    found = dict(_names("src/client.ts", text))
    assert found["Client::request"] == "public"
    assert found["Client::send"] == "private"
    assert found["Client::retry"] == "private"


def test_python_uses_the_underscore_convention():
    text = ("def urlize(text):\n    return _escape(text)\n\n"
            "def _escape(text):\n    return text\n")
    found = dict(_names("src/jinja2/utils.py", text))
    assert found["urlize"] == "public"
    assert found["_escape"] == "private"


def test_python_all_overrides_the_convention():
    text = ("__all__ = ['urlize']\n\n"
            "def urlize(t):\n    return t\n\n"
            "def helper(t):\n    return t\n")
    found = dict(_names("u.py", text))
    assert found["urlize"] == "public"
    assert found["helper"] == "private", "__all__ задаёт публичность явно"


def test_python_methods_carry_their_class():
    text = ("class Environment:\n"
            "    def get_template(self, name):\n        return self._load(name)\n\n"
            "    def _load(self, name):\n        return name\n")
    found = dict(_names("env.py", text))
    assert found["Environment::get_template"] == "public"
    assert found["Environment::_load"] == "private"


def test_go_visibility_is_the_case_of_the_first_letter():
    text = ("package x\n\n"
            "func Parse(s string) error { return validate(s) }\n\n"
            "func validate(s string) error { return nil }\n\n"
            "func (c *Client) Do(r *Request) error { return nil }\n")
    found = dict(_names("x.go", text))
    assert found["Parse"] == "public"
    assert found["validate"] == "private"
    assert found["Client::Do"] == "public"


def test_an_unknown_language_declares_nothing():
    assert language_of("README.rst") is None
    assert declarations("README.rst", "def looks_like_python():") == []


# --- the bridge across each language ---------------------------------------

def test_bridge_finds_the_public_caller_in_javascript():
    source = {"lib/adapters/http.js": (
        "function setProxy(options, proxy) { return proxy; }\n"
        "export function httpAdapter(config) {\n"
        "  return setProxy(config.options, config.proxy);\n}\n")}
    result = find_bridge("setProxy", source, parent_package="axios")
    assert result.calls_it is True
    assert [str(s) for s in result.public_symbols] == ["httpAdapter"]


def test_bridge_finds_the_public_caller_in_python():
    source = {"src/jinja2/filters.py": (
        "def do_xmlattr(d):\n    return _escape(d)\n\n"
        "def _escape(d):\n    return d\n")}
    result = find_bridge("_escape", source, parent_package="jinja2")
    assert [str(s) for s in result.public_symbols] == ["do_xmlattr"]


def test_bridge_finds_the_public_caller_in_go():
    source = {"parse.go": (
        "package x\n\nfunc Parse(s string) error { return decode(s) }\n\n"
        "func decode(s string) error { return nil }\n")}
    result = find_bridge("decode", source, parent_package="example/x")
    assert [str(s) for s in result.public_symbols] == ["Parse"]


def test_a_language_we_cannot_parse_is_not_a_closure():
    """No parser means no callers found, which must not read as "never calls it"."""
    result = find_bridge("isValid", {"lib/main.rb": "def send(a); validate(a); end"},
                         parent_package="some/gem")
    assert result.calls_it is None
    assert result.closes is False
    assert "не разбирается" in result.detail


def test_enclosing_ignores_declarations_after_the_position():
    text = "def first():\n    flag()\n\ndef second():\n    pass\n"
    found = enclosing("m.py", text, text.index("flag("))
    assert found is not None and found.name == "first"
