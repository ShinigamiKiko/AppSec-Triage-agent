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
    EvidenceClass,
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
