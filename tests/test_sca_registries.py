"""Library source comes from the installed tree, and from nowhere else.

The rule is not a preference. Downloading a published archive sends the
project's dependency list to a third party and pulls foreign code into the
scanning container, and a scanner must do neither. So the only question these
tests answer is whether the code is read from disk correctly, and whether its
absence is reported as absence rather than worked around.
"""

from __future__ import annotations

from appsec_triage.sca import registries


def _install(tmp_path, relative, files):
    directory = tmp_path / relative
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return directory


def test_a_composer_package_is_read_from_vendor(tmp_path):
    _install(tmp_path, "vendor/guzzlehttp/guzzle",
             {"src/Cookie/SetCookie.php": "<?php function matchesDomain($d) {}"})

    files = registries.package_source("composer", "guzzlehttp/guzzle", "7.4.1", tmp_path)

    assert "src/Cookie/SetCookie.php" in files
    assert "matchesDomain" in files["src/Cookie/SetCookie.php"]


def test_an_npm_package_is_read_from_node_modules(tmp_path):
    _install(tmp_path, "node_modules/axios", {"lib/axios.js": "function request() {}"})
    files = registries.package_source("npm", "axios", "0.21.0", tmp_path)
    assert "lib/axios.js" in files


def test_a_scoped_npm_package_keeps_its_scope(tmp_path):
    _install(tmp_path, "node_modules/@scope/parser", {"index.js": "function parse() {}"})
    files = registries.package_source("npm", "@scope/parser", "1.0.0", tmp_path)
    assert "index.js" in files


def test_a_python_package_is_read_from_site_packages(tmp_path):
    _install(tmp_path, ".venv/lib/python3.12/site-packages/jinja2",
             {"utils.py": "def urlize(text):\n    return text\n"})
    files = registries.package_source("pypi", "jinja2", "2.11.2", tmp_path)
    assert "utils.py" in files


def test_a_package_that_is_not_installed_returns_nothing(tmp_path):
    """Empty means "could not check", and the caller must not read it as
    "the symbol is not there"."""
    assert registries.package_source("composer", "twig/twig", "3.3.8", tmp_path) == {}


def test_no_root_means_no_source(tmp_path):
    """There is no fallback that reaches the network."""
    assert registries.package_source("composer", "twig/twig", "3.3.8") == {}


def test_tests_and_docs_inside_a_package_are_skipped(tmp_path):
    _install(tmp_path, "vendor/acme/lib", {
        "src/Real.php": "<?php class Real {}",
        "tests/RealTest.php": "<?php class RealTest {}",
        "docs/guide.php": "<?php",
    })
    files = registries.package_source("composer", "acme/lib", "1.0.0", tmp_path)
    assert list(files) == ["src/Real.php"]


def test_nothing_in_this_module_opens_a_connection():
    """A regression guard: the previous version fetched archives over HTTP."""
    source = (registries.__file__)
    text = open(source, encoding="utf-8").read()
    for forbidden in ("urllib", "requests", "http", "socket"):
        assert forbidden not in text.lower().replace("https://", ""), (
            f"модуль снова умеет ходить в сеть: {forbidden}")
