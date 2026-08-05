"""Reading the Symfony container, because the source does not hold the answer.

`$this->decorated->onAuthenticationFailure()` has a declared type of
`AuthenticatorInterface` and a concrete class named only in `services.yaml`. A
language server cannot infer it and, measured, did not try: two answers out of
five positions on a fully installed project, one of them wrong. Configuration
states it outright.

The failure to guard against is the quiet one: Symfony's YAML carries custom
tags, `safe_load` refuses the whole document over one of them, and refusing the
document loses every service in it. That was measured as zero configuration
files read on a project with a fully wired container.
"""

from __future__ import annotations

from appsec_triage.sca import container


def _project(tmp_path, services_yaml, files: dict[str, str] | None = None):
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "config" / "services.yaml").write_text(services_yaml, encoding="utf-8")
    for name, body in (files or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def test_an_interface_alias_resolves_to_the_class():
    wiring = container.Wiring(
        classes={"App\\Service\\ChatBotServiceInterface": "App\\Service\\ChatBotService"})
    assert wiring.resolve("App\\Service\\ChatBotServiceInterface") == "App\\Service\\ChatBotService"


def test_an_at_alias_resolves_through_the_service_id():
    wiring = container.Wiring(
        aliases={"App\\MainAppServiceInterface": "App\\MainAppService"},
        classes={"App\\MainAppService": "App\\MainAppService"})
    assert wiring.resolve("App\\MainAppServiceInterface") == "App\\MainAppService"


def test_an_unresolved_dotted_id_is_not_returned_as_a_class():
    """`Ats.security.authenticator` is a service id declared by a bundle. It is
    not a class, and returning it as one would name something that cannot be
    searched for."""
    wiring = container.Wiring(decorates={"App\\Decorator": "Ats.security.authenticator"})
    assert wiring.resolve("Ats.security.authenticator") == ""


def test_symfony_custom_tags_do_not_lose_the_whole_file(tmp_path):
    """Measured: zero files read on a project whose container was fully wired."""
    root = _project(tmp_path, (
        "parameters:\n"
        "    locales: !php/const App\\Locale::SUPPORTED\n"
        "services:\n"
        "    App\\ChatBotServiceInterface:\n"
        "        class: App\\ChatBotService\n"
        "    App\\Collector:\n"
        "        arguments: [!tagged_iterator app.checks]\n"
    ))
    wiring = container.load(root)

    assert wiring.usable, f"конфигурация не прочитана: {wiring.problem}"
    assert wiring.resolve("App\\ChatBotServiceInterface") == "App\\ChatBotService"


def test_a_decorator_resolves_to_the_service_it_decorates(tmp_path):
    root = _project(
        tmp_path,
        (
            "services:\n"
            "    App\\Security\\Decorator:\n"
            "        decorates: 'app.real_authenticator'\n"
            "        arguments:\n"
            "            $decorated: '@.inner'\n"
            "    app.real_authenticator:\n"
            "        class: App\\Security\\RealAuthenticator\n"
        ),
        {"src/Security/Decorator.php": (
            "<?php\nnamespace App\\Security;\n"
            "class Decorator implements AuthenticatorInterface\n{\n"
            "    private AuthenticatorInterface $decorated;\n"
            "    public function __construct(AuthenticatorInterface $decorated) {}\n}\n"
        )},
    )
    wiring = container.load(root)
    text = (root / "src/Security/Decorator.php").read_text(encoding="utf-8")

    found = container.receiver_class(wiring, text, "$this->decorated")
    assert found.klass == "RealAuthenticator"
    assert "decorates" in found.via


def test_a_decorated_service_declared_by_a_bundle_says_how_to_check(tmp_path):
    """From a real project: `decorates: 'Ats.security.authenticator'`, a service
    no file in the repository defines."""
    root = _project(
        tmp_path,
        ("services:\n"
         "    App\\Security\\Decorator:\n"
         "        decorates: 'Ats.security.authenticator'\n"
         "        arguments:\n"
         "            $decorated: '@.inner'\n"),
        {"src/Security/Decorator.php": (
            "<?php\nnamespace App\\Security;\n"
            "class Decorator\n{\n    private AuthenticatorInterface $decorated;\n}\n")},
    )
    wiring = container.load(root)
    text = (root / "src/Security/Decorator.php").read_text(encoding="utf-8")

    found = container.receiver_class(wiring, text, "$this->decorated")
    assert found.klass == ""
    assert "Ats.security.authenticator" in found.detail
    assert "debug:container" in found.detail, "не сказано, как это проверить"


def test_property_types_are_read_from_both_spellings():
    typed = ("<?php\nclass A { private AuthenticatorInterface $decorated; }\n")
    promoted = ("<?php\nclass A {\n"
                "  public function __construct(private LoggerInterface $logger) {}\n}\n")
    assert container.property_type(typed, "decorated") == "AuthenticatorInterface"
    assert container.property_type(promoted, "logger") == "LoggerInterface"


def test_scalar_property_types_are_not_classes():
    text = "<?php\nclass A { private string $name; private array $items; }\n"
    assert container.property_type(text, "name") == ""
    assert container.property_type(text, "items") == ""


def test_a_project_without_config_says_so(tmp_path):
    wiring = container.load(tmp_path)
    assert wiring.usable is False
    assert "нет каталога config" in wiring.problem
