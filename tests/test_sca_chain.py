"""The four-step chain, including the ways it is allowed to fail.

The tests that matter most here are the negative ones. A presence check that
counts a comment, or a reachability check that reads a missing tool as "no
path", would both close real vulnerabilities silently — and both are easy to
write by accident.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from types import SimpleNamespace

from appsec_triage.sca.advisories import Advisory, _rank_refs
from appsec_triage.sca.presence import SymbolPresence, find_symbol
from appsec_triage.sca.resolve import SymbolResolver
from appsec_triage.sca.reach import ReachResult, Reachability, needs_input_path
from appsec_triage.sca.resolve import VulnerableSymbol
from appsec_triage.sca.verdict import CVEVerdict, decide


class _FakeClient:
    """Answers with a fixed payload, so the chain is tested and not the provider."""

    def __init__(self, answer: dict) -> None:
        self._answer = {"vulnerable_function": "", "vulnerable_class": "",
                        "vulnerable_file": "", "evidence": "", "why": "", **answer}

    def complete(self, system, user, json_schema=None):
        return SimpleNamespace(text=json.dumps(self._answer))


class _MustNotCallModel:
    def complete(self, *args, **kwargs):
        raise AssertionError("govulncheck evidence must not be re-inferred by a model")


class _ScriptedClient:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.calls = []

    def complete(self, system, user, json_schema=None):
        self.calls.append((system, user, json_schema))
        return SimpleNamespace(text=self.answers.pop(0))


def _php(tmp_path, name, body):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --- step 3: presence ------------------------------------------------------


def test_govulncheck_no_symbol_call_is_a_deterministic_closure(tmp_path):
    from appsec_triage.models import CodeContext, DependencyInfo, Finding
    from appsec_triage.sca.chain import DependencyChain

    finding = Finding(
        finding_id="govulncheck:GO-2099-1:example.com/lib",
        scanner="govulncheck",
        rule_id="GO-2099-1",
        code_context=CodeContext(file_path="go.mod"),
        dependency=DependencyInfo(
            package="example.com/lib",
            ecosystem="go",
            installed_version="v1.0.0",
            fixed_versions=["v1.0.1"],
        ),
    )

    result = DependencyChain(_MustNotCallModel(), [tmp_path]).run(finding)

    assert result.closes
    assert result.decision.verdict is CVEVerdict.NO_VULNERABLE_SYMBOL
    assert "symbol-level" in result.decision.headline


def test_govulncheck_call_trace_is_used_without_symbol_extraction(tmp_path):
    from appsec_triage.models import CodeContext, DependencyInfo, Finding, TraceStep
    from appsec_triage.sca.chain import DependencyChain

    finding = Finding(
        finding_id="govulncheck:GO-2099-2:example.com/lib",
        scanner="govulncheck",
        rule_id="GO-2099-2",
        code_context=CodeContext(file_path="cmd/app/main.go", start_line=12),
        trace=[
            TraceStep(
                file_path="cmd/app/main.go",
                line=12,
                message="example.com/app.main",
                role="source",
            ),
            TraceStep(
                file_path="example.com/lib@v1.0.0/parser.go",
                line=40,
                message="example.com/lib.Parse",
                role="sink",
            ),
        ],
        source="example.com/app.main",
        sink="example.com/lib.Parse",
        dependency=DependencyInfo(
            package="example.com/lib",
            ecosystem="go",
            installed_version="v1.0.0",
            fixed_versions=["v1.0.1"],
        ),
    )

    result = DependencyChain(_MustNotCallModel(), [tmp_path]).run(finding)

    assert result.decision.verdict is CVEVerdict.ACTUAL
    assert result.symbol is not None
    assert result.symbol.function == "Parse"
    assert result.presence is not None
    assert str(result.presence.hits[0]) == "cmd/app/main.go:12"


def test_govulncheck_uses_targeted_codeql_path_even_without_cwe(tmp_path):
    from appsec_triage.models import CodeContext, DependencyInfo, Finding, TraceStep
    from appsec_triage.sca.chain import DependencyChain

    finding = Finding(
        finding_id="govulncheck:GO-2099-3:example.com/lib",
        scanner="govulncheck",
        rule_id="GO-2099-3",
        code_context=CodeContext(file_path="api/handler.go", start_line=41),
        trace=[
            TraceStep(file_path="api/handler.go", line=41, message="app.Handle", role="source"),
            TraceStep(file_path="lib/parser.go", line=9, message="lib.Parse", role="sink"),
        ],
        source="app.Handle",
        sink="lib.Parse",
        dependency=DependencyInfo(package="example.com/lib", ecosystem="go", installed_version="v1.0.0"),
    )
    codeql = Finding(
        finding_id="targeted",
        scanner="codeql",
        rule_id="go/govulncheck-targeted-taint",
        code_context=CodeContext(file_path="api/handler.go", start_line=41),
        trace=[
            TraceStep(file_path="api/bind.go", line=12, role="source"),
            TraceStep(file_path="api/handler.go", line=41, role="sink"),
        ],
    )

    result = DependencyChain(_MustNotCallModel(), [tmp_path]).run(
        finding, codeql_findings=[codeql]
    )

    assert result.reach is not None
    assert "api/bind.go:12 -> api/handler.go:41" in result.reach.taint_path
    assert "CodeQL targeted dataflow" in result.render()

def test_method_call_is_found(tmp_path):
    _php(tmp_path, "src/Controller.php", "<?php\n$jar->extractCookies($req, $res);\n")
    result = find_symbol(tmp_path, function="extractCookies")
    assert result.presence is SymbolPresence.CALLED
    assert result.hits[0].line == 2


def test_php_call_matching_ignores_case(tmp_path):
    """PHP method names are case-insensitive, so the search must be too."""
    _php(tmp_path, "src/W.php", "<?php\n$w->generateHtmlAll();\n")
    assert find_symbol(tmp_path, function="generateHTMLAll").presence is SymbolPresence.CALLED


def test_declaring_a_method_is_not_calling_one(tmp_path):
    """Measured on an unseen project: a controller's own `login()` action was
    reported as a call to `Security::login` from symfony/security-bundle. Any
    project method sharing a name with a vulnerable one would have matched."""
    _php(tmp_path, "src/Controller/SecurityController.php",
         "<?php\nclass SecurityController\n{\n"
         "    public function login(AuthenticationUtils $utils): Response\n"
         "    {\n        return $this->render('login.html.twig');\n    }\n}\n")

    result = find_symbol(tmp_path, function="login")
    assert result.presence is SymbolPresence.ABSENT


def test_a_real_call_to_the_same_name_still_counts(tmp_path):
    _php(tmp_path, "src/Service/Auth.php",
         "<?php\n$security->login($user);\n")
    assert find_symbol(tmp_path, function="login").presence is SymbolPresence.CALLED


def test_a_go_method_with_a_receiver_is_a_declaration(tmp_path):
    """Measured on hugo: `func (s *Site) render(...)` was reported as a call to
    `golang.org/x/net`'s `render`. A lookbehind for `func ` cannot see it — the
    receiver sits between the keyword and the name, so the line is what has to
    be checked."""
    (tmp_path / "site.go").write_text(
        "package hugolib\n"
        "import \"golang.org/x/net/html\"\n"
        "func (s *Site) render(ctx *siteRenderContext) (err error) {\n"
        "\treturn nil\n}\n",
        encoding="utf-8")

    result = find_symbol(tmp_path, function="render", ecosystem="go",
                         package="golang.org/x/net")
    assert result.presence is not SymbolPresence.CALLED


def test_a_real_go_call_still_counts(tmp_path):
    (tmp_path / "use.go").write_text(
        "package main\n"
        "import \"golang.org/x/net/html\"\n"
        "func main() {\n\thtml.Render(w, node)\n}\n",
        encoding="utf-8")

    result = find_symbol(tmp_path, function="Render", ecosystem="go",
                         package="golang.org/x/net")
    assert result.presence is SymbolPresence.CALLED


def test_declarations_are_skipped_in_every_language(tmp_path):
    (tmp_path / "a.py").write_text("def urlize(text):\n    return text\n", encoding="utf-8")
    (tmp_path / "b.go").write_text("func Parse(s string) error { return nil }\n",
                                   encoding="utf-8")
    assert find_symbol(tmp_path, function="urlize", ecosystem="pypi",
                       package="jinja2").presence is SymbolPresence.ABSENT
    assert find_symbol(tmp_path, function="Parse", ecosystem="go",
                       package="example/x").presence is SymbolPresence.ABSENT


def test_mention_in_a_comment_is_not_a_call(tmp_path):
    _php(tmp_path, "src/N.php",
         "<?php\n// TODO: extractCookies() is deprecated\n/* extractCookies() */\n")
    result = find_symbol(tmp_path, function="extractCookies")
    assert result.presence is SymbolPresence.ABSENT


def test_vendor_tree_is_not_our_code(tmp_path):
    """The library calls its own internals; matching there reports everything."""
    _php(tmp_path, "vendor/guzzle/Cookie.php", "<?php\n$this->matchesDomain($d);\n")
    assert find_symbol(tmp_path, function="matchesDomain").presence is SymbolPresence.ABSENT


def test_absent_is_not_phrased_as_safe(tmp_path):
    _php(tmp_path, "src/A.php", "<?php\necho 1;\n")
    result = find_symbol(tmp_path, function="matchesDomain")
    assert result.presence is SymbolPresence.ABSENT
    assert "внутри библиотеки" in result.detail


def test_class_without_call_is_only_a_reference(tmp_path):
    _php(tmp_path, "src/B.php", "<?php\nuse GuzzleHttp\\Cookie\\SetCookie;\n")
    result = find_symbol(tmp_path, function="matchesDomain", klass="SetCookie")
    assert result.presence is SymbolPresence.REFERENCED


def test_an_npm_package_is_not_searched_for_in_go_files(tmp_path):
    """Measured on traefik: `axios::merge` matched `pkg/provider/configuration.go`,
    `lodash::trim` a Go integration test, `json5::push` an array push — five npm
    advisories reported as called, every one in the wrong language."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "configuration.go").write_text(
        "package pkg\nfunc x() { merge(a, b) }\n", encoding="utf-8")

    result = find_symbol(tmp_path, function="merge", ecosystem="npm", package="axios")
    assert result.presence is SymbolPresence.ABSENT
    assert "нет файлов на языке пакета" in result.detail


def test_a_javascript_call_needs_the_package_imported(tmp_path):
    """`json5.push` in a file that never requires json5 is `Array.push`."""
    (tmp_path / "helpers.js").write_text(
        "const items = [];\nitems.push(value);\n", encoding="utf-8")

    result = find_symbol(tmp_path, function="push", ecosystem="npm", package="json5")
    assert result.presence is not SymbolPresence.CALLED


def test_an_imported_npm_package_does_count(tmp_path):
    (tmp_path / "client.js").write_text(
        "const axios = require('axios');\naxios.request(config);\n", encoding="utf-8")

    result = find_symbol(tmp_path, function="request", ecosystem="npm", package="axios")
    assert result.presence is SymbolPresence.CALLED


def test_esm_and_scoped_imports_are_recognised(tmp_path):
    (tmp_path / "a.mjs").write_text(
        "import { parse } from '@scope/parser';\nparse(input);\n", encoding="utf-8")
    result = find_symbol(tmp_path, function="parse", ecosystem="npm",
                         package="@scope/parser")
    assert result.presence is SymbolPresence.CALLED


def test_a_python_import_anchors_the_call(tmp_path):
    (tmp_path / "app.py").write_text(
        "from jinja2 import Environment\nEnvironment().urlize(text)\n", encoding="utf-8")
    result = find_symbol(tmp_path, function="urlize", ecosystem="pypi", package="jinja2")
    assert result.presence is SymbolPresence.CALLED


def test_a_class_named_in_a_bundle_list_is_not_a_call(tmp_path):
    """Measured: 12 of 17 "actual" verdicts rested on `config/bundles.php` and
    `src/Kernel.php`, where classes are registered and nothing is invoked."""
    _php(tmp_path, "config/bundles.php",
         "<?php\nreturn [\n  Symfony\\Bundle\\TwigBundle\\TwigBundle::class => ['all' => true],\n];\n")
    result = find_symbol(tmp_path, function="checkSecurity", klass="TwigBundle")
    assert result.presence is SymbolPresence.REFERENCED

    decision = decide(
        VulnerableSymbol("GHSA-a", "twig/twig", function="checkSecurity",
                         klass="TwigBundle", confirmed_in_source=True),
        result, None, cwe="CWE-94")
    assert decision.verdict is CVEVerdict.MENTIONED_ONLY
    assert "не вызывается" in decision.headline


def test_the_word_appearing_somewhere_does_not_bind_the_class(tmp_path):
    """`Request::create` was reported in a Doctrine entity because the word
    "Request" appeared there in an unrelated context."""
    _php(tmp_path, "src/Entity/ApplicationImageOption.php",
         "<?php\n// a field describing an image request option\n"
         "class ApplicationImageOption { public function create() {} }\n"
         "$x = $this->create();\n")
    result = find_symbol(tmp_path, function="create", klass="Request")
    assert result.presence is not SymbolPresence.CALLED


def test_an_imported_class_does_bind_it(tmp_path):
    _php(tmp_path, "src/Controller/A.php",
         "<?php\nuse Symfony\\Component\\HttpFoundation\\Request;\n"
         "$r = Request::create('/x');\n")
    result = find_symbol(tmp_path, function="create", klass="Request")
    assert result.presence is SymbolPresence.CALLED


def test_calls_only_in_tests_are_not_an_attack_surface(tmp_path):
    _php(tmp_path, "tests/Unit/ThingTest.php",
         "<?php\nuse GuzzleHttp\\Cookie\\SetCookie;\n$c->matchesDomain($h);\n")
    result = find_symbol(tmp_path, function="matchesDomain", klass="SetCookie")
    assert result.presence is SymbolPresence.CALLED
    assert result.only_in_tests is True

    decision = decide(
        VulnerableSymbol("GHSA-b", "guzzlehttp/guzzle", function="matchesDomain",
                         klass="SetCookie", confirmed_in_source=True),
        result, None, cwe="CWE-79")
    assert decision.verdict is CVEVerdict.ONLY_IN_TESTS
    assert not decision.closes


def test_a_production_call_outweighs_test_calls(tmp_path):
    _php(tmp_path, "tests/Unit/ThingTest.php",
         "<?php\nuse GuzzleHttp\\Cookie\\SetCookie;\n$c->matchesDomain($h);\n")
    _php(tmp_path, "src/Http/Client.php",
         "<?php\nuse GuzzleHttp\\Cookie\\SetCookie;\n$c->matchesDomain($h);\n")
    result = find_symbol(tmp_path, function="matchesDomain", klass="SetCookie")
    assert result.only_in_tests is False
    assert any(not h.in_tests for h in result.hits)


def test_a_common_method_name_alone_is_not_a_call_to_this_library(tmp_path):
    """Measured on a real project: `AbstractAdapterTrait::clear` from
    symfony/cache matched `$em->clear()` in a Doctrine repository, and
    `SandboxExtension::getAttribute` from twig matched an LDAP provider."""
    _php(tmp_path, "src/Repository/Images.php",
         "<?php\nuse Doctrine\\ORM\\EntityManager;\n$em->clear();\n")
    result = find_symbol(tmp_path, function="clear", klass="AbstractAdapterTrait")
    assert result.presence is not SymbolPresence.CALLED
    assert "класс объекта не подтверждён" in result.detail


def test_a_common_name_counts_once_the_class_is_in_scope(tmp_path):
    _php(tmp_path, "src/Cache.php",
         "<?php\nuse Symfony\\Component\\Cache\\Traits\\AbstractAdapterTrait;\n$a->clear();\n")
    result = find_symbol(tmp_path, function="clear", klass="AbstractAdapterTrait")
    assert result.presence is SymbolPresence.CALLED


def test_a_call_whose_class_is_not_in_scope_is_only_a_reference(tmp_path):
    """Measured: `$container->getParameter()` was reported as
    `ParameterizedHeader::getParameter`. Restricting the class requirement to a
    list of common names cannot work — the list is never complete."""
    _php(tmp_path, "src/Compiler.php", "<?php\n$container->getParameter('roles');\n")
    result = find_symbol(tmp_path, function="getParameter", klass="ParameterizedHeader")
    assert result.presence is SymbolPresence.CALL_UNCONFIRMED
    assert result.presence is not SymbolPresence.CALLED


def test_a_call_through_an_interface_is_not_called_only_mentioned(tmp_path):
    """From a real project: `$this->decorated->onAuthenticationFailure()` in a
    decorator. The call is real and the concrete class is not visible, so
    neither "called" nor "only mentioned" is a true description of it."""
    _php(tmp_path, "src/Security/Decorator.php",
         "<?php\nuse Symfony\\Component\\Security\\Guard\\AuthenticatorInterface;\n"
         "$this->decorated->onAuthenticationFailure($request, $exception);\n")
    result = find_symbol(tmp_path, function="onAuthenticationFailure",
                         klass="DefaultAuthenticationFailureHandler")
    assert result.presence is SymbolPresence.CALL_UNCONFIRMED

    decision = decide(
        VulnerableSymbol("GHSA-c", "symfony/security-http",
                         function="onAuthenticationFailure",
                         klass="DefaultAuthenticationFailureHandler",
                         confirmed_in_source=True),
        result, None, cwe="CWE-601")
    assert decision.verdict is CVEVerdict.CALL_UNCONFIRMED
    assert not decision.closes
    assert "языковой сервер" in " ".join(decision.reasons)


def test_a_name_with_no_class_at_all_still_counts(tmp_path):
    """A global function has no class to bind, so nothing to require."""
    _php(tmp_path, "src/Http.php", "<?php\ntwig_array_column($rows, 'x');\n")
    result = find_symbol(tmp_path, function="twig_array_column")
    assert result.presence is SymbolPresence.CALLED


def test_comments_do_not_shift_the_reported_line(tmp_path):
    """A hit reported at a line that does not contain it is unreviewable."""
    _php(tmp_path, "src/Late.php",
         "<?php\n/*\n multi\n line\n comment\n*/\n"
         "use GuzzleHttp\\Cookie\\SetCookie;\n$c->matchesDomain($h);\n")
    result = find_symbol(tmp_path, function="matchesDomain", klass="SetCookie")
    assert result.presence is SymbolPresence.CALLED
    assert result.hits[0].line == 8, f"строка {result.hits[0].line} вместо 8"


def test_not_distributed_short_circuits_the_search(tmp_path):
    result = find_symbol(tmp_path, file_hint="samples/Convert-Online.php", not_distributed=True)
    assert result.presence is SymbolPresence.NOT_DISTRIBUTED


# --- step 2: resolution, live ----------------------------------------------

def test_fix_references_are_ranked_commit_first():
    """A release tag bundles several fixes; a commit is one."""
    advisory = Advisory(
        advisory_id="GHSA-x",
        fix_refs=_rank_refs([
            "https://github.com/o/r/security/advisories/GHSA-x",
            "https://github.com/o/r/pull/42",
            "https://github.com/o/r/commit/1dd98b0564cb3f6bd16ce683cb755f94c10fbd82",
        ]),
    )
    assert advisory.fix_refs[0].endswith("commit/1dd98b0564cb3f6bd16ce683cb755f94c10fbd82")
    assert not any("security/advisories" in ref for ref in advisory.fix_refs)


def test_a_database_timing_out_is_not_reported_as_no_vulnerabilities(monkeypatch):
    """Measured: one run found ten advisories for jinja2, the next found zero,
    because the query timed out and the empty list looked like a clean package."""
    from appsec_triage.sca import advisories as adv

    def boom(*args, **kwargs):
        raise adv.DatabaseUnavailable("api.osv.dev -> timed out")

    monkeypatch.setattr(adv, "_get_json", boom)
    with pytest.raises(adv.DatabaseUnavailable):
        adv.from_osv("jinja2", "pypi", "2.11.2")

    merged = adv.collect(package="jinja2", ecosystem="pypi", version="2.11.2")
    assert "базы не ответили" in merged.problem


def test_a_real_404_is_an_answer_not_an_outage(monkeypatch):
    import urllib.error

    from appsec_triage.sca import advisories as adv

    def missing(*args, **kwargs):
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, None)

    monkeypatch.setattr(adv.urllib.request, "urlopen", missing)
    assert adv.from_osv("nope", "pypi", "1.0.0") == []




def test_declarations_are_recognised_in_every_language_we_scan():
    """Matching only `function name(` reported every Python symbol as absent."""
    from appsec_triage.sca.resolve import _declared

    files = {
        "src/jinja2/utils.py": "def urlize(text, trim_url_limit=None):\n    pass\n",
        "src/a.php": "<?php\nclass X { public function matchesDomain($d) {} }\n",
        "lib/http.js": "var setProxy = function (options, proxy) {};\n",
        "lib/arrow.js": "const mergeConfig = (a, b) => a;\n",
    }
    assert _declared("urlize", files) == ["src/jinja2/utils.py"]
    assert _declared("matchesDomain", files) == ["src/a.php"]
    assert _declared("setProxy", files) == ["lib/http.js"]
    assert _declared("mergeConfig", files) == ["lib/arrow.js"]
    assert _declared("nowhere", files) == []






def test_a_name_absent_from_the_fix_is_dropped(monkeypatch):
    """The check that caught `setProxy` for an axios version with no such
    function. It needs neither the package nor an installed tree: a fix changes
    the vulnerable function, so its name is in the diff."""
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff",
                        lambda advisory: ("--- a/lib/http.js\n+ function httpAdapter() {}", "u"))

    resolver = SymbolResolver(_FakeClient({"vulnerable_function": "setProxy"}))
    symbol = resolver.resolve(
        Advisory("GHSA-a", package="axios", ecosystem="npm", details="text"), "0.21.0")

    assert symbol.function == ""
    assert symbol.grounded_in_fix is False
    assert "не встречается" in symbol.note


def test_malformed_symbol_json_is_repaired_once(monkeypatch):
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))
    client = _ScriptedClient(
        '{"vulnerable_function":"matchesDomain" "vulnerable_class":"SetCookie"}',
        json.dumps({
            "vulnerable_function": "matchesDomain",
            "vulnerable_class": "SetCookie",
            "vulnerable_file": "src/Cookie/SetCookie.php",
            "evidence": "matchesDomain",
            "why": "cookie domain comparison",
        }),
    )

    symbol = SymbolResolver(client).resolve(Advisory(
        "GHSA-json", package="guzzlehttp/guzzle", ecosystem="composer",
        details="SetCookie::matchesDomain compares cookie domains",
    ), "7.4.1")

    assert symbol.function == "matchesDomain"
    assert symbol.resolution_error == ""
    assert len(client.calls) == 2
    assert "JSON CORRECTION REQUIRED" in client.calls[1][1]
    assert "JSON does not support `=>`" in client.calls[1][1]
    assert "Parser error:" in client.calls[1][1]


def test_symbol_json_wrappers_are_removed_without_a_second_call(monkeypatch):
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))
    client = _ScriptedClient(
        '```json\n{"vulnerable_function":"matchesDomain","vulnerable_class":"SetCookie"}\n```'
    )

    symbol = SymbolResolver(client).resolve(Advisory(
        "GHSA-fence", package="guzzlehttp/guzzle", ecosystem="composer",
        details="SetCookie::matchesDomain compares cookie domains",
    ), "7.4.1")

    assert symbol.function == "matchesDomain"
    assert len(client.calls) == 1


def test_two_malformed_symbol_answers_remain_visible(monkeypatch):
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))
    client = _ScriptedClient('{"broken": first}', '{"still_broken": second}')

    symbol = SymbolResolver(client).resolve(
        Advisory("GHSA-bad-json", package="p/q", ecosystem="composer", details="prose"), "1.0"
    )

    assert symbol.function == ""
    assert "invalid JSON twice" in symbol.resolution_error
    assert "first_response" in symbol.resolution_error
    assert "repair_response" in symbol.resolution_error
    assert symbol.resolution_error.startswith(symbol.note)
    assert len(client.calls) == 2


def test_a_name_present_in_the_fix_is_kept(monkeypatch):
    from appsec_triage.sca import resolve as resolve_mod

    # A patch to an existing function shows that function in its pre-image —
    # on a removed line or in context. A name that appears only on added lines
    # is a function the fix created, which is a different case entirely.
    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: (
        "@@ function httpAdapter(config) @@\n"
        "-   return setProxy(config);\n"
        "+   return applyProxy(config);\n", "u"))

    resolver = SymbolResolver(_FakeClient(
        {"vulnerable_function": "httpAdapter",
         "evidence": "-   return setProxy(config);"}))
    symbol = resolver.resolve(
        Advisory("GHSA-b", package="axios", ecosystem="npm", details="text"), "0.21.0")

    assert symbol.function == "httpAdapter"
    assert symbol.grounded_in_fix is True
    assert symbol.existed_before_fix is True


def test_a_name_only_in_the_advisory_text_still_counts(monkeypatch):
    """Many advisories name the symbol in prose and link no usable commit."""
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))

    resolver = SymbolResolver(_FakeClient({"vulnerable_function": "matchesDomain"}))
    symbol = resolver.resolve(
        Advisory("GHSA-c", package="guzzlehttp/guzzle", ecosystem="composer",
                 details="SetCookie::matchesDomain() removes leading dots"), "7.4.1")

    assert symbol.function == "matchesDomain"
    assert symbol.grounded_in_fix is True


def test_no_diff_and_no_mention_is_reported_as_unverified(monkeypatch):
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))

    resolver = SymbolResolver(_FakeClient({"vulnerable_function": "whatever"}))
    symbol = resolver.resolve(
        Advisory("GHSA-d", package="p/q", ecosystem="composer", details="prose"), "1.0")

    assert symbol.function == "whatever", "без диффа отбрасывать нельзя — это не доказательство"
    assert symbol.grounded_in_fix is False
    assert "ничем не подтверждено" in symbol.note


def _resolver_with(monkeypatch, answer, diff="", installed=None):
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: (diff, "u" if diff else ""))
    monkeypatch.setattr(resolve_mod.registries, "supported", lambda eco: True)
    monkeypatch.setattr(resolve_mod.registries, "package_source",
                        lambda eco, name, version="", root=None: installed or {})
    return SymbolResolver(_FakeClient(answer), roots=[Path("/nonexistent")])


def test_the_two_checks_are_independent_and_both_can_drop_a_name(monkeypatch):
    """A function the fix never touched is not the flaw; a function the
    installed version does not declare cannot be called here. Either alone is
    enough to drop the name."""
    advisory = Advisory("GHSA-x", package="p/q", ecosystem="composer", details="prose")

    # Grounded in the fix, but absent from the installed tree.
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "findCharSet"},
        diff="+ function findCharSet() {}",
        installed={"src/X.php": "<?php function toUtf8() {}"})
    symbol = resolver.resolve(advisory, "1.29.0")
    assert symbol.function == ""
    assert "нет в уязвимой версии" in symbol.note

    # Declared in the installed tree, but the fix never mentions it.
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "toUtf8"},
        diff="+ function findCharSet() {}",
        installed={"src/X.php": "<?php function toUtf8() {}"})
    symbol = resolver.resolve(advisory, "1.29.0")
    assert symbol.function == ""
    assert "не встречается" in symbol.note


def test_a_function_the_fix_created_is_dropped_without_reading_the_package():
    """`findCharSet` does not exist in the vulnerable release — the fix added
    it. The diff alone says so: a name that appears only on `+` lines was not
    in the pre-image, so no project can contain it."""
    from appsec_triage.sca.resolve import _existed_before_fix

    diff = ("@@ private function toUtf8($x) @@\n"
            "-   $charset = 'UTF-8';\n"
            "+   $charset = $this->findCharSet($x);\n"
            "+ private function findCharSet($x) { return 'UTF-8'; }\n")

    assert _existed_before_fix("findCharSet", diff) is False
    assert _existed_before_fix("toUtf8", diff) is True
    assert _existed_before_fix("anything", "") is None


def test_a_quote_from_an_unchanged_line_drops_the_name(monkeypatch):
    """The bypassed validator sits in the diff untouched. Quoting it is exactly
    how the wrong function gets named — the Twig `validateName` case."""
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "validateName",
                      "evidence": "  $this->validateName($name);"},
        diff=("@@ findTemplate @@\n"
              "   $this->validateName($name);\n"
              "-  return $this->paths[$namespace];\n"
              "+  return $this->resolve($namespace, $name);\n"))
    symbol = resolver.resolve(
        Advisory("GHSA-t", package="twig/twig", ecosystem="composer", details="prose"),
        "3.3.8")

    assert symbol.function == ""
    assert "фикс не менял" in symbol.note


def test_what_the_fix_changed_is_recorded(monkeypatch):
    """Asking for the behaviour forces the diff to be read; a summary that only
    repeats the function name is an answer pattern-matched from the title."""
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "matchesDomain",
                      "evidence": "+ $cookieDomain = \\ltrim(\\strtolower($d), '.');",
                      "what_changed": "сравнение домена стало регистронезависимым"},
        diff=("@@ public function matchesDomain(string $d): bool @@\n"
              "+ $cookieDomain = \\ltrim(\\strtolower($d), '.');\n"))
    symbol = resolver.resolve(
        Advisory("GHSA-c", package="guzzlehttp/guzzle", ecosystem="composer",
                 details="prose"), "7.4.1")

    assert symbol.function == "matchesDomain"
    assert symbol.what_changed == "сравнение домена стало регистронезависимым"
    assert symbol.quotes_a_changed_line is True


def test_a_dropped_name_is_not_described_as_corroborated(monkeypatch):
    """From `ip-address`: the fix did name the function, the installed version
    has no such function, the name was dropped — and the summary still read
    "the fix changed this function"."""
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "isInSubnetNew",
                      "vulnerable_file": "src/ipv4.ts"},
        diff="+ function isInSubnetNew() {}",
        installed={"dist/common.js": "function isInSubnet() {}"})
    symbol = resolver.resolve(
        Advisory("GHSA-i", package="ip-address", ecosystem="npm", details="prose"), "8.1.0")

    assert symbol.function == ""
    assert "фикс правил эту функцию" not in symbol.strength
    assert "нет в уязвимой версии" in symbol.strength


def test_both_checks_agreeing_is_reported_as_the_strongest(monkeypatch):
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "toUtf8",
                      "evidence": "- function toUtf8($x) {}"},
        diff="- function toUtf8($x) {}",
        installed={"src/X.php": "<?php function toUtf8() {}"})
    symbol = resolver.resolve(
        Advisory("GHSA-y", package="p/q", ecosystem="composer", details="prose"), "1.29.0")

    assert symbol.function == "toUtf8"
    assert symbol.grounded_in_fix is True
    assert symbol.declared_in_installed is True
    assert "подтверждено дважды" in symbol.strength


def test_no_installed_tree_is_not_treated_as_absence(monkeypatch):
    """Without `vendor/` the second check does not run — and "not checked" must
    never read as "not there"."""
    resolver = _resolver_with(
        monkeypatch, {"vulnerable_function": "toUtf8",
                      "evidence": "- function toUtf8($x) {}"},
        diff="- function toUtf8($x) {}", installed={})
    symbol = resolver.resolve(
        Advisory("GHSA-z", package="p/q", ecosystem="composer", details="prose"), "1.29.0")

    assert symbol.function == "toUtf8"
    assert symbol.declared_in_installed is None
    assert "сверить не с чем" in symbol.strength


def test_unfetchable_source_leaves_the_symbol_unconfirmed(monkeypatch):
    """No network is "could not confirm", never "the symbol is not there"."""
    from appsec_triage.sca import resolve as resolve_mod

    monkeypatch.setattr(resolve_mod, "fix_diff", lambda advisory: ("", ""))
    monkeypatch.setattr(resolve_mod.registries, "package_source",
                        lambda eco, name, version="", root=None: {})

    resolver = SymbolResolver(_FakeClient({"vulnerable_function": "matchesDomain"}))
    symbol = resolver.resolve(
        Advisory("GHSA-z", package="p/q", ecosystem="composer", details="text"), "7.4.1")
    assert symbol.function == "matchesDomain"
    assert symbol.confirmed_in_source is False


def test_advisory_with_nothing_to_read_is_reported_not_guessed():
    resolver = SymbolResolver(_FakeClient({"vulnerable_function": "whatever"}))
    symbol = resolver.resolve(Advisory("GHSA-empty", package="p/q"))
    assert symbol.function == ""
    assert symbol.note


# --- step 4: reachability --------------------------------------------------

def test_xss_requires_an_input_path_and_a_cipher_does_not():
    assert needs_input_path("CWE-79") is True
    assert needs_input_path("CWE-327") is False


def test_missing_tool_never_reads_as_not_reachable():
    reach = ReachResult(Reachability.UNKNOWN, tools_missing=["codeql (не отработал)"])
    decision = decide(
        VulnerableSymbol("GHSA-x", "p", function="generateRow", confirmed_in_source=True),
        find_symbol_stub(), reach, cwe="CWE-79",
    )
    assert decision.verdict is CVEVerdict.PRESENT_UNPROVEN
    assert not decision.closes


def test_both_tools_agreeing_makes_it_actual():
    reach = ReachResult(Reachability.REACHABLE, entrypoint="GET /export",
                        taint_path="Controller.php:10 -> Html.php:44",
                        tools_used=["lsp", "codeql"])
    decision = decide(
        VulnerableSymbol("GHSA-x", "p", function="generateRow", confirmed_in_source=True),
        find_symbol_stub(), reach, cwe="CWE-79",
    )
    assert decision.verdict is CVEVerdict.ACTUAL
    assert "достижима извне" in decision.headline


def test_flaw_without_input_needs_only_the_call():
    decision = decide(
        VulnerableSymbol("GHSA-y", "p", function="gzfileGetContents", confirmed_in_source=True),
        find_symbol_stub(), None, cwe="CWE-400",
    )
    assert decision.verdict is CVEVerdict.ACTUAL


def test_a_build_only_dependency_is_closed_without_the_model():
    """It never runs where an attacker can reach it, and the SBOM says so."""
    decision = decide(
        VulnerableSymbol("GHSA-d", "phpunit/phpunit", function="run"),
        find_symbol_stub(), None, cwe="CWE-79", dev_only=True)

    assert decision.verdict is CVEVerdict.NOT_SHIPPED
    assert decision.closes


def test_a_direct_library_the_repository_never_names_is_closed():
    decision = decide(
        VulnerableSymbol("GHSA-e", "some/tool", function="run"),
        find_symbol_stub(), None, cwe="CWE-918", direct=True,
        used=False, used_detail="ни одно из имён не встречается")

    assert decision.verdict is CVEVerdict.UNUSED
    assert decision.closes
    assert any("контейнер" in r for r in decision.reasons), (
        "предел этого довода должен быть назван"
    )


def test_a_transitive_library_the_repository_never_names_is_not_closed():
    """Measured: `aws/aws-sdk-php` was closed as unused on a project that
    reaches it through `league/flysystem`. The AWS code runs; the application
    simply never writes `Aws\\` itself, which is what transitive means."""
    decision = decide(
        VulnerableSymbol("GHSA-e", "aws/aws-sdk-php", function="buildEndpoint"),
        find_symbol_stub(), None, cwe="CWE-918", direct=False,
        used=False, used_detail="ни одно из имён (Aws) не встречается")

    assert decision.verdict is CVEVerdict.NO_DIRECT_CALL
    assert not decision.closes
    assert any("родитель" in r for r in decision.reasons)


def test_a_used_library_is_not_closed_by_that_check():
    decision = decide(
        VulnerableSymbol("GHSA-f", "guzzlehttp/guzzle", function="matchesDomain"),
        find_symbol_stub(), None, cwe="CWE-79", used=True)
    assert decision.verdict is not CVEVerdict.UNUSED


def test_an_unmet_precondition_closes_it():
    from appsec_triage.sca.conditions import Condition, ConditionState

    condition = Condition(ConditionState.ABSENT, "приложение рендерит пользовательские шаблоны",
                          ["createTemplate"], "контроллеры", reason="просмотрено 400 файлов")
    decision = decide(
        VulnerableSymbol("GHSA-g", "twig/twig", function="checkSecurity"),
        find_symbol_stub(), None, cwe="CWE-94", condition=condition)

    assert decision.verdict is CVEVerdict.CONDITION_ABSENT
    assert decision.closes


def test_an_external_precondition_does_not_close():
    """"Not decidable here" is a question for a person, not a closure."""
    from appsec_triage.sca.conditions import Condition, ConditionState

    condition = Condition(ConditionState.EXTERNAL, "внешние сущности XML включены",
                          ["LIBXML_NOENT"], "php.ini", reason="задаётся вне репозитория")
    decision = decide(
        VulnerableSymbol("GHSA-h", "p/q", function="load"),
        find_symbol_stub(), None, cwe="CWE-611", condition=condition)

    assert not decision.closes


def test_only_not_distributed_closes_anything():
    decision = decide(
        VulnerableSymbol("GHSA-z", "p", file="samples/x.php", not_distributed=True),
        None, None, cwe="CWE-79",
    )
    assert decision.verdict is CVEVerdict.NOT_APPLICABLE
    assert decision.closes


def test_no_direct_call_is_not_a_closure(tmp_path):
    _php(tmp_path, "src/A.php", "<?php\necho 1;\n")
    decision = decide(
        VulnerableSymbol("GHSA-w", "p", function="matchesDomain", confirmed_in_source=True),
        find_symbol(tmp_path, function="matchesDomain"), None, cwe="CWE-79",
    )
    assert decision.verdict is CVEVerdict.NO_DIRECT_CALL
    assert not decision.closes
    assert any("закрывать нельзя" in r for r in decision.reasons)


def find_symbol_stub():
    """A presence result standing for "called here", without touching disk."""
    from appsec_triage.sca.presence import Hit, PresenceResult

    return PresenceResult(SymbolPresence.CALLED, "generateRow",
                          [Hit("src/Export.php", 44, "$w->generateRow($row);")])
