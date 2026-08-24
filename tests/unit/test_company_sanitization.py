"""Tests for the YouTrack-backed company dictionary redactor."""

from unittest.mock import Mock

import pytest

from youtrack_mcp.company_sanitization import (
    CompanyDictionaryError,
    CompanyDictionaryRedactor,
    YouTrackCompanyLoader,
)
from youtrack_mcp.sanitization import OutputSanitizationBoundary


@pytest.mark.unit
def test_loader_reads_all_values_from_project_client_enum():
    client = Mock()
    client.get.side_effect = [
        [
            {
                "id": "project-field-1",
                "field": {"name": "Клиент"},
                "bundle": {"id": "bundle-1"},
            }
        ],
        [
            {"id": "company-1", "name": "РКЦ Прогресс"},
            {
                "id": "company-2",
                "name": "Сибирская угольная энергетическая компания",
            },
        ],
    ]

    names = YouTrackCompanyLoader(client)()

    assert names == [
        "РКЦ Прогресс",
        "Сибирская угольная энергетическая компания",
    ]
    assert client.get.call_args_list[0].args == ("admin/projects/SUP/customFields",)
    assert client.get.call_args_list[1].args == (
        "admin/customFieldSettings/bundles/enum/bundle-1/values",
    )
    assert client.get.call_args_list[1].kwargs["params"]["fields"] == "id,name"


@pytest.mark.unit
def test_full_names_words_and_acronyms_share_company_aliases():
    redactor = CompanyDictionaryRedactor(
        lambda: [
            "РКЦ Прогресс",
            "Сибирская угольная энергетическая компания",
            "Газпром нефть",
        ],
        key="test-key",
    )

    result = redactor.redact(
        {
            "rkc": "РКЦ сообщил",
            "progress": "Прогресс сообщил",
            "suek": "СУЭК сообщил",
            "suek_full": "Сибирская\u00a0угольная энергетическая компания сообщила",
            "gazprom_full": "Газпром нефть сообщила",
            "gazprom_acronym": "ГН сообщила",
        }
    )

    assert result["rkc"].split()[0] == result["progress"].split()[0]
    assert result["suek"].split()[0] == result["suek_full"].split()[0]
    assert result["gazprom_full"].split()[0] == result["gazprom_acronym"].split()[0]
    assert all(value.startswith("COMPANY-") for value in result.values())
    assert redactor.redact("РП остается без замены") == "РП остается без замены"


@pytest.mark.unit
def test_legal_form_does_not_suppress_derived_acronym():
    redactor = CompanyDictionaryRedactor(
        lambda: ["ООО Сибирская угольная энергетическая компания"],
        key="test-key",
    )

    full_name = redactor.redact("ООО Сибирская угольная энергетическая компания")
    acronym = redactor.redact("СУЭК")

    assert acronym == full_name
    assert acronym.startswith("COMPANY-")


@pytest.mark.unit
def test_uppercase_long_words_do_not_suppress_derived_acronym():
    redactor = CompanyDictionaryRedactor(
        lambda: ["СИБИРСКАЯ УГОЛЬНАЯ ЭНЕРГЕТИЧЕСКАЯ КОМПАНИЯ"],
        key="test-key",
    )

    assert redactor.redact("СУЭК").startswith("COMPANY-")


@pytest.mark.unit
def test_company_names_are_redacted_inside_error_payloads():
    redactor = CompanyDictionaryRedactor(lambda: ["РКЦ Прогресс"], key="test-key")
    assert redactor.redact({"error": "Ошибка РКЦ"})["error"].startswith(
        "Ошибка COMPANY-"
    )


@pytest.mark.unit
def test_ambiguous_individual_word_is_not_replaced():
    redactor = CompanyDictionaryRedactor(
        lambda: ["Альфа Прогресс", "РКЦ Прогресс"],
        key="test-key",
    )

    assert redactor.redact("Прогресс") == "Прогресс"
    assert redactor.redact("Альфа Прогресс").startswith("COMPANY-")
    assert redactor.redact("РКЦ Прогресс").startswith("COMPANY-")


@pytest.mark.unit
def test_dictionary_refreshes_after_configured_interval():
    now = [100.0]
    loader = Mock(return_value=["РКЦ Прогресс"])
    redactor = CompanyDictionaryRedactor(
        loader,
        key="test-key",
        refresh_seconds=86400,
        clock=lambda: now[0],
    )

    redactor.redact("РКЦ")
    now[0] += 86399
    redactor.redact("РКЦ")
    assert loader.call_count == 1

    now[0] += 1
    redactor.redact("РКЦ")
    assert loader.call_count == 2


@pytest.mark.unit
def test_refresh_failure_retains_last_successful_dictionary():
    now = [100.0]
    loader = Mock(side_effect=[["РКЦ Прогресс"], RuntimeError("offline")])
    redactor = CompanyDictionaryRedactor(
        loader,
        key="test-key",
        refresh_seconds=10,
        clock=lambda: now[0],
    )

    expected = redactor.redact("РКЦ")
    now[0] += 10

    assert redactor.redact("РКЦ") == expected
    assert expected.startswith("COMPANY-")


@pytest.mark.unit
def test_initial_refresh_failure_is_fail_closed_when_required():
    redactor = CompanyDictionaryRedactor(
        Mock(side_effect=RuntimeError("offline")),
        key="test-key",
        required=True,
    )

    with pytest.raises(CompanyDictionaryError):
        redactor.redact("РКЦ")


@pytest.mark.unit
def test_company_redaction_runs_before_central_sidecar():
    class RecordingPassthrough:
        def __init__(self):
            self.payload = None

        def sanitize(self, tool_name, payload):
            self.payload = payload
            return payload

    backend = RecordingPassthrough()
    redactor = CompanyDictionaryRedactor(
        lambda: ["РКЦ Прогресс"],
        key="test-key",
    )
    boundary = OutputSanitizationBoundary(
        backend,
        preprocessors=(redactor,),
    )

    result = boundary.sanitize("get_issue", {"description": "РКЦ Прогресс"})

    assert result["description"].startswith("COMPANY-")
    assert backend.payload == result
