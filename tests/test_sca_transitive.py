"""A CVE in a transitive package, which is most of them.

Two failures this guards against, both of which make a report useless rather
than wrong-looking:

Telling a developer to upgrade a package whose version they do not control. A
transitive version is pinned by its parent's constraint, and "update to 3.2.1"
is then advice nobody can follow.

Reading "the application never calls the vulnerable function" as a closure. Of
course it does not — it calls the parent. The only absence that means anything
is the parent not calling it either.
"""

from __future__ import annotations

import json
from pathlib import Path

from appsec_triage.sca.bridge import find_bridge
from appsec_triage.sca.graph import DependencyGraph


def _sbom(components, dependencies, root="root"):
    """A CycloneDX document, the only shape the graph accepts."""
    return {
        "metadata": {"component": {"bom-ref": root}},
        "components": components,
        "dependencies": dependencies,
    }


def _graph(components, dependencies, root="root"):
    return DependencyGraph._from_sbom(_sbom(components, dependencies, root))


# --- the graph -------------------------------------------------------------

def test_a_transitive_package_names_the_parent_that_pins_it():
    graph = _graph(
        [{"bom-ref": "m", "purl": "pkg:composer/symfony/mailer@5.4.3"},
         {"bom-ref": "v", "purl": "pkg:composer/egulias/email-validator@2.1.25"}],
        [{"ref": "root", "dependsOn": ["m"]}, {"ref": "m", "dependsOn": ["v"]}],
    )
    placement = graph.placement("egulias/email-validator")

    assert placement.direct is False
    assert placement.parents == ["symfony/mailer"]
    assert "symfony/mailer -> egulias/email-validator" in placement.describe()
    assert "напрямую не обновить" in placement.upgrade_note()


def test_a_direct_dependency_is_reported_as_upgradable():
    graph = _graph([{"bom-ref": "t", "purl": "pkg:composer/twig/twig@3.3.8"}],
                   [{"ref": "root", "dependsOn": ["t"]}])
    placement = graph.placement("twig/twig")
    assert placement.direct is True
    assert "composer.json" in placement.upgrade_note()


def test_every_path_that_introduces_a_package_is_kept():
    """Upgrading one parent does not help when another pins the same package."""
    graph = _graph(
        [{"bom-ref": "a", "purl": "pkg:composer/a/one@1.0.0"},
         {"bom-ref": "b", "purl": "pkg:composer/b/two@1.0.0"},
         {"bom-ref": "s", "purl": "pkg:composer/shared/lib@1.0.0"}],
        [{"ref": "root", "dependsOn": ["a", "b"]},
         {"ref": "a", "dependsOn": ["s"]},
         {"ref": "b", "dependsOn": ["s"]}],
    )
    assert sorted(graph.placement("shared/lib").parents) == ["a/one", "b/two"]


def test_an_sbom_without_root_edges_cannot_call_anything_direct():
    """Everything would look transitive, which is a claim, not an absence."""
    graph = _graph([{"bom-ref": "x", "purl": "pkg:composer/x/y@1.0"}], [])
    assert "прямые зависимости не определить" in graph.placement("x/y").problem


def test_a_package_missing_from_the_sbom_says_so():
    graph = _graph([{"bom-ref": "x", "purl": "pkg:composer/x/y@1.0"}],
                   [{"ref": "root", "dependsOn": ["x"]}])
    assert "нет в SBOM" in graph.placement("other/pkg").problem


def test_without_cdxgen_there_is_no_graph_and_it_is_stated(tmp_path, monkeypatch):
    """The lockfile parser is gone on purpose: one source, one answer. Its
    absence must be visible rather than filled in by a worse one."""
    from appsec_triage.sca import graph as graph_mod

    monkeypatch.setattr(graph_mod.sbom_mod, "available", lambda: None)
    built = graph_mod.DependencyGraph.from_project(tmp_path)

    assert built.usable is False
    assert "cdxgen не установлен" in built.problem
    assert "cdxgen не установлен" in built.placement("x/y").problem


def test_a_failing_cdxgen_is_reported_not_replaced(tmp_path, monkeypatch):
    from appsec_triage.sca import graph as graph_mod

    monkeypatch.setattr(graph_mod.sbom_mod, "available", lambda: "/usr/bin/cdxgen")
    monkeypatch.setattr(graph_mod.sbom_mod, "generate",
                        lambda root, **kw: (None, "cdxgen не уложился в 600s"))
    built = graph_mod.DependencyGraph.from_project(tmp_path)

    assert built.usable is False
    assert "не уложился" in built.problem


def test_the_graph_has_no_lockfile_parser_left():
    """A regression guard: a second source is what this change removed."""
    from appsec_triage.sca import graph as graph_mod

    source = Path(graph_mod.__file__).read_text(encoding="utf-8")
    assert "composer.lock" not in source
    assert "_from_composer" not in source


def test_the_graph_comes_from_an_sbom_for_any_ecosystem():
    """cdxgen states the edges directly, so npm and PyPI need no new parser."""
    document = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [
            {"bom-ref": "a", "purl": "pkg:npm/express@4.17.1"},
            {"bom-ref": "b", "purl": "pkg:npm/qs@6.7.0"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["a"]},
            {"ref": "a", "dependsOn": ["b"]},
        ],
    }
    graph = DependencyGraph._from_sbom(document)
    assert graph.version_of("qs") == "6.7.0"

    placement = graph.placement("qs")
    assert placement.direct is False
    assert placement.parents == ["express"]
    assert placement.describe().startswith("транзитивная")


def test_a_namespaced_purl_keeps_its_full_package_name():
    """Dropping the namespace made OSV return nothing for "guzzle"."""
    from appsec_triage.sca.sbom import parse_purl

    assert parse_purl("pkg:composer/guzzlehttp/guzzle@7.4.1") == (
        "composer", "guzzlehttp/guzzle", "7.4.1")
    assert parse_purl("pkg:npm/%40babel/core@7.0.0") == ("npm", "@babel/core", "7.0.0")
    assert parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0") == (
        "go", "github.com/gin-gonic/gin", "v1.9.0")


def test_the_manifest_named_is_the_one_that_ecosystem_uses():
    """Measured: "обновляется напрямую в composer.json" was printed for a Go
    module and for an npm package — advice nobody can follow."""
    document = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [
            {"bom-ref": "g", "purl": "pkg:golang/github.com/go-ldap/ldap/v3@3.4.1"},
            {"bom-ref": "a", "purl": "pkg:npm/puppeteer@13.0.0"},
            {"bom-ref": "b", "purl": "pkg:npm/ip-address@8.1.0"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["g", "a"]},
            {"ref": "a", "dependsOn": ["b"]},
        ],
    }
    graph = DependencyGraph._from_sbom(document)

    assert "go.mod" in graph.placement("github.com/go-ldap/ldap/v3").upgrade_note()
    transitive = graph.placement("ip-address").upgrade_note()
    assert "overrides в package.json" in transitive
    assert "composer" not in transitive


def test_build_only_components_are_marked_dev():
    document = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [{"bom-ref": "t", "purl": "pkg:composer/phpunit/phpunit@9.5",
                        "scope": "excluded"}],
        "dependencies": [{"ref": "root", "dependsOn": ["t"]}],
    }
    graph = DependencyGraph._from_sbom(document)
    assert graph.placement("phpunit/phpunit").dev_only is True


# --- the bridge ------------------------------------------------------------

_PARENT = {
    "src/Mailer.php": (
        "<?php\n"
        "class Mailer\n"
        "{\n"
        "    public function send(string $address): void\n"
        "    {\n"
        "        $this->check($address);\n"
        "    }\n"
        "\n"
        "    private function check(string $address): bool\n"
        "    {\n"
        "        return $this->validator->isValid($address);\n"
        "    }\n"
        "}\n"
    )
}


def test_the_parent_functions_that_reach_the_flaw_are_named():
    result = find_bridge("isValid", _PARENT, parent_package="symfony/mailer")
    assert result.calls_it is True
    assert [str(s) for s in result.symbols] == ["Mailer::check"]
    assert result.symbols[0].visibility == "private"


def test_a_parent_that_never_calls_it_closes_the_path():
    """The only absence that means anything: the caller is the parent, not us."""
    result = find_bridge("matchesDomain", _PARENT, parent_package="symfony/mailer")
    assert result.closes is True
    assert "нигде не вызывает" in result.detail


def test_unreadable_parent_source_is_not_a_closure():
    result = find_bridge("isValid", {}, parent_package="symfony/mailer")
    assert result.calls_it is None
    assert result.closes is False
    assert "не получены" in result.detail


def test_only_public_parent_functions_are_worth_searching_for():
    source = {
        "src/A.php": (
            "<?php\n"
            "class Client\n"
            "{\n"
            "    public function request($u)\n"
            "    {\n"
            "        return $this->jar->matchesDomain($u);\n"
            "    }\n"
            "}\n"
        )
    }
    result = find_bridge("matchesDomain", source, parent_package="guzzlehttp/guzzle")
    assert [str(s) for s in result.public_symbols] == ["Client::request"]


# --- the chain putting both to use -----------------------------------------

def _chain(tmp_path, monkeypatch, parent_source, graph):
    from appsec_triage.sca import chain as chain_mod

    monkeypatch.setattr(chain_mod.registries, "supported", lambda eco: True)
    monkeypatch.setattr(chain_mod.registries, "package_source",
                        lambda eco, name, version="", root=None: parent_source)

    built = chain_mod.DependencyChain(object(), [tmp_path])
    built._graphs[str(tmp_path)] = graph
    return built


_TRANSITIVE = ([{"bom-ref": "m", "purl": "pkg:composer/symfony/mailer@5.4.3"},
                {"bom-ref": "v", "purl": "pkg:composer/egulias/email-validator@2.1.25"}],
               [{"ref": "root", "dependsOn": ["m"]}, {"ref": "m", "dependsOn": ["v"]}])


def test_an_internal_flaw_is_searched_for_by_the_parents_public_api(tmp_path, monkeypatch):
    """The application cannot call `isValid`; it calls `Mailer::send`."""
    from appsec_triage.sca.resolve import VulnerableSymbol

    chain = _chain(tmp_path, monkeypatch, {
        "src/Mailer.php": (
            "<?php\nclass Mailer\n{\n    public function send($a)\n    {\n"
            "        return $this->validator->isValid($a);\n    }\n}\n"
        )
    }, _graph(*_TRANSITIVE))
    symbol = VulnerableSymbol("GHSA-x", "egulias/email-validator", function="isValid")
    placement = chain._placement("egulias/email-validator")

    bridge, targets = chain._bridge(symbol, placement, _Dep("composer"))

    assert bridge is not None and bridge.calls_it is True
    assert targets == [("send", "Mailer")], "искать надо публичный метод посредника"


def test_a_parent_that_never_calls_it_leaves_nothing_to_search(tmp_path, monkeypatch):
    from appsec_triage.sca.resolve import VulnerableSymbol

    chain = _chain(tmp_path, monkeypatch, {
        "src/Mailer.php": "<?php\nclass Mailer { public function send($a) { return $a; } }\n"
    }, _graph(*_TRANSITIVE))
    symbol = VulnerableSymbol("GHSA-x", "egulias/email-validator", function="isValid")

    bridge, targets = chain._bridge(symbol, chain._placement("egulias/email-validator"),
                                    _Dep("composer"))
    assert bridge is not None and bridge.closes is True
    assert targets == []


def test_a_direct_dependency_is_searched_for_by_its_own_symbol(tmp_path, monkeypatch):
    from appsec_triage.sca.resolve import VulnerableSymbol

    chain = _chain(tmp_path, monkeypatch, {}, _graph(
        [{"bom-ref": "t", "purl": "pkg:composer/twig/twig@3.3.8"}],
        [{"ref": "root", "dependsOn": ["t"]}]))
    symbol = VulnerableSymbol("GHSA-y", "twig/twig", function="findTemplate",
                              klass="FilesystemLoader")

    bridge, targets = chain._bridge(symbol, chain._placement("twig/twig"), _Dep("composer"))
    assert bridge is None
    assert targets == [("findTemplate", "FilesystemLoader")]


class _Dep:
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem
