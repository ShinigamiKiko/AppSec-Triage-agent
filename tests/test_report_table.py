"""The summary table — the part of the report a person reads first.

Collapsible cards are fine for one finding and useless for sixty: nothing can be
scanned, compared or sorted. The table answers, per row, the four questions a
reviewer actually has — what it is, whether this code is affected, where to
look, and what was followed to decide.

The fifth column exists because "we could not tell from the code" is a different
answer from "no", and burying it in prose loses the distinction that took the
whole chain to establish.
"""

from __future__ import annotations

from appsec_triage.models import (
    DataflowStep,
    EvidenceClass,
    ExternalControlReference,
    SCASummary,
    TriageRecord,
    Verdict,
    VerdictLabel,
)
from appsec_triage.pipeline import TriageRun
from appsec_triage.report.html import render


def _record(**over) -> TriageRecord:
    base = dict(
        finding_id="f1", cwe="CWE-79", file_path="src/Export.php",
        kind="dependency", start_line=44,
        verdict=Verdict(verdict=VerdictLabel.confirmed,
                        evidence_class=EvidenceClass.identifier_only,
                        confidence=0.8, cwe="CWE-79", reason="ships an affected version"),
    )
    base.update(over)
    return TriageRecord(**base)


def _run(*records) -> TriageRun:
    return TriageRun(records=list(records), provider="deepseek",
                     model="deepseek-chat", prompt_pack="default")


def test_a_reachable_finding_names_file_line_and_symbol():
    record = _record(sca=SCASummary(
        package="guzzlehttp/guzzle", installed_version="7.4.1",
        symbol="SetCookie::matchesDomain",
        outcome="actual", outcome_note="вызывается и достижима извне",
        call_sites=["src/Http/Client.php:31"],
        trace="src/Controller/A.php:10 -> src/Http/Client.php:31"))

    page = render(_run(record))

    assert "guzzlehttp/guzzle" in page
    assert "src/Http/Client.php:31" in page
    assert "SetCookie::matchesDomain" in page
    assert "src/Controller/A.php:10 -&gt; src/Http/Client.php:31" in page


def test_an_external_condition_gets_its_own_column_with_what_to_check():
    record = _record(sca=SCASummary(
        package="phpoffice/phpspreadsheet", installed_version="1.29.0",
        symbol="XmlScanner::toUtf8", outcome="undecided",
        external="загрузка внешних XML-сущностей включена — искать: LIBXML_NOENT; "
                 "где: php.ini и переменные окружения"))

    page = render(_run(record))

    assert "EXTERNAL" in page
    assert "LIBXML_NOENT" in page
    assert "php.ini" in page


def test_sca_symbol_resolution_error_is_visible_in_the_finding_card():
    record = _record(sca=SCASummary(
        package="guzzlehttp/guzzle",
        resolution_error="invalid JSON twice near CookieJar::extractCookies",
    ))

    page = render(_run(record))

    assert "SCA symbol resolution error" in page
    assert "invalid JSON twice near CookieJar::extractCookies" in page


def test_an_infrastructure_finding_names_the_owner():
    record = _record(sca=SCASummary(
        package="symfony/ldap", outcome="infrastructure",
        external="LDAP-сервер разрешает незашифрованные соединения",
        owner="команда каталога"))

    page = render(_run(record))

    assert "инфраструктура" in page
    assert "команда каталога" in page


def test_the_answer_column_is_yes_no_or_not_established():
    page = render(_run(
        _record(finding_id="a"),
        _record(finding_id="b", verdict=Verdict(
            verdict=VerdictLabel.false_positive, evidence_class=EvidenceClass.identifier_only,
            confidence=0.9, cwe="CWE-79", reason="build-only")),
        _record(finding_id="c", verdict=Verdict(
            verdict=VerdictLabel.unknown, evidence_class=EvidenceClass.identifier_only,
            confidence=0.4, cwe="CWE-79", reason="не решено")),
    ))

    assert ">да<" in page
    assert ">нет<" in page
    assert ">не установлено<" in page


def test_external_fp_is_shown_as_ai_closed_with_its_control():
    external = _record(
        verdict=Verdict(
            verdict=VerdictLabel.external_fp,
            evidence_class=EvidenceClass.exploitable_dataflow,
            confidence=0.85,
            cwe="CWE-89",
            reason="the path exists but the WAF covers it",
            external_control=ExternalControlReference(
                control_id="public-waf",
                why_effective="verified policy covers this route",
            ),
            requires_human_review=False,
        )
    )
    page = render(_run(external))

    assert "митигировано извне" in page
    assert "External mitigated" in page
    assert "public-waf" in page
    assert "Что нужно от тебя" not in page


def test_confirmed_findings_come_first():
    """The table is a queue: what needs a person is at the top."""
    page = render(_run(
        _record(finding_id="closed", file_path="zzz.php", verdict=Verdict(
            verdict=VerdictLabel.false_positive, evidence_class=EvidenceClass.identifier_only,
            confidence=0.9, cwe="CWE-79", reason="closed")),
        _record(finding_id="open", file_path="aaa.php"),
    ))
    table = page.split('<table class="findings">')[1]
    assert table.index("aaa.php") < table.index("zzz.php")


def test_a_first_party_finding_still_fills_the_row():
    """Not every finding is a dependency; the table is the same table."""
    record = _record(kind="weakness", sca=None, cwe="CWE-89",
                     file_path="src/Repository/User.php", start_line=88)
    page = render(_run(record))

    assert "CWE-89" in page
    assert "src/Repository/User.php:88" in page


def test_a_first_party_dataflow_uses_the_schema_location():
    record = _record(
        kind="weakness",
        sca=None,
        verdict=Verdict(
            verdict=VerdictLabel.confirmed,
            evidence_class=EvidenceClass.exploitable_dataflow,
            confidence=0.9,
            cwe="CWE-89",
            reason="request data reaches the query",
            dataflow=[
                DataflowStep(
                    order=1,
                    role="sink",
                    location="src/Repository/User.php:88",
                    code="$connection->executeQuery($sql);",
                )
            ],
        ),
    )

    page = render(_run(record))

    assert "src/Repository/User.php:88 sink" in page


def test_report_has_a_separate_four_state_priority_column():
    from appsec_triage.models import Priority

    record = _record(priority=Priority.critical, priority_score=91)
    page = render(_run(record))

    assert "<th>Priority</th>" in page
    assert "priority-critical" in page
    assert ">Critical<" in page
