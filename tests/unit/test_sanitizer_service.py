"""Unit tests for structural output policies without loading NLP models."""

import pytest

from sanitizer_service.service import (
    OutputPolicy,
    PolicyViolation,
    PresidioAndSecretsSanitizer,
)


class FakeTextSanitizer:
    def sanitize(self, text: str) -> str:
        return (
            text.replace("Ivan Ivanov", "[PERSON]")
            .replace("ivan@example.com", "[EMAIL_ADDRESS]")
            .replace("top-secret", "[SECRET]")
        )


@pytest.fixture
def policy():
    return OutputPolicy(FakeTextSanitizer(), profile="strict")


def test_issue_policy_drops_identity_and_unknown_fields(policy):
    result = policy.sanitize(
        "get_issue",
        {
            "idReadable": "DEMO-1",
            "summary": "Ivan Ivanov reported a problem",
            "description": "Email ivan@example.com, token top-secret",
            "reporter": {"name": "Ivan Ivanov", "email": "ivan@example.com"},
            "assignee": {"login": "ivan"},
            "internalUrl": "https://internal.example/DEMO-1",
            "customFields": [
                {"name": "Priority", "value": {"name": "Major", "id": "1-1"}},
                {"name": "Customer", "value": "Secret Corp"},
            ],
        },
    )

    assert result == {
        "id": "DEMO-1",
        "summary": "[PERSON] reported a problem",
        "description": "Email [EMAIL_ADDRESS], token [SECRET]",
        "customFields": [{"name": "Priority", "value": {"name": "Major"}}],
    }


def test_comment_policy_drops_author(policy):
    result = policy.sanitize(
        "get_issue_comments",
        [
            {
                "text": "Contact Ivan Ivanov at ivan@example.com",
                "author": {"name": "Ivan Ivanov", "login": "ivan"},
                "created": 123,
            }
        ],
    )

    assert result == [{"text": "Contact [PERSON] at [EMAIL_ADDRESS]", "created": 123}]


def test_article_policy_keeps_readable_content_and_drops_identity(policy):
    result = policy.sanitize(
        "get_article",
        {
            "id": "226-0",
            "idReadable": "DOC-A-1",
            "summary": "Инструкция Ivan Ivanov",
            "content": "Напишите на ivan@example.com; token top-secret",
            "reporter": {"name": "Ivan Ivanov"},
            "project": {"id": "0-1", "shortName": "DOC", "name": "Документация"},
            "updated": 123,
            "visibility": {"permittedUsers": [{"login": "ivan"}]},
        },
    )

    assert result == {
        "id": "DOC-A-1",
        "summary": "Инструкция [PERSON]",
        "content": "Напишите на [EMAIL_ADDRESS]; token [SECRET]",
        "updated": 123,
        "project": {"shortName": "DOC", "name": "Документация"},
    }


def test_article_search_policy_sanitizes_each_result(policy):
    result = policy.sanitize(
        "search_articles",
        [
            {
                "idReadable": "DOC-A-2",
                "summary": "Кодировка UTF-8",
                "content": "Контакт Ivan Ivanov",
            }
        ],
    )

    assert result == [
        {
            "id": "DOC-A-2",
            "summary": "Кодировка UTF-8",
            "content": "Контакт [PERSON]",
        }
    ]


def test_article_id_is_not_changed_by_text_sanitization():
    class LocationSanitizer:
        def sanitize(self, text: str) -> str:
            return text.replace("LOC", "[LOCATION]")

    location_policy = OutputPolicy(LocationSanitizer(), profile="strict")
    result = location_policy.sanitize(
        "get_article",
        {"idReadable": "LOC-A-12", "summary": "LOC guide"},
    )

    assert result["id"] == "LOC-A-12"
    assert result["summary"] == "[LOCATION] guide"


def test_comment_policy_batches_text_sanitization():
    class BatchTextSanitizer:
        def __init__(self):
            self.batches = []

        def sanitize(self, text: str) -> str:
            raise AssertionError("comments must use batch sanitization")

        def sanitize_many(self, texts: list[str]) -> list[str]:
            self.batches.append(texts)
            return [text.replace("secret", "[SECRET]") for text in texts]

    text_sanitizer = BatchTextSanitizer()
    batch_policy = OutputPolicy(text_sanitizer, profile="strict")
    comments = [{"text": f"comment {index} secret"} for index in range(20)]

    result = batch_policy.sanitize("get_issue_comments", comments)

    assert text_sanitizer.batches == [
        [f"comment {index} secret" for index in range(20)]
    ]
    assert [comment["text"] for comment in result] == [
        f"comment {index} [SECRET]" for index in range(20)
    ]


def test_presidio_batch_runs_only_two_language_analyses():
    class RecordingAnalyzer:
        def __init__(self):
            self.calls = []

        def analyze(self, *, text, language, score_threshold):
            self.calls.append((text, language, score_threshold))
            return []

    sanitizer = PresidioAndSecretsSanitizer.__new__(PresidioAndSecretsSanitizer)
    sanitizer._analyzer = RecordingAnalyzer()
    sanitizer._score_threshold = 0.4
    sanitizer._redact_secrets = lambda text: text

    texts = [f"Комментарий {index}" for index in range(20)]
    result = sanitizer.sanitize_many(texts)

    assert result == texts
    assert [call[1] for call in sanitizer._analyzer.calls] == ["ru", "en"]


def test_presidio_batch_limits_combined_document_size():
    class RecordingAnalyzer:
        def __init__(self):
            self.calls = []

        def analyze(self, *, text, language, score_threshold):
            self.calls.append((text, language, score_threshold))
            return []

    sanitizer = PresidioAndSecretsSanitizer.__new__(PresidioAndSecretsSanitizer)
    sanitizer._analyzer = RecordingAnalyzer()
    sanitizer._score_threshold = 0.4
    sanitizer._batch_max_chars = 25
    sanitizer._redact_secrets = lambda text: text

    texts = [str(index) * 10 for index in range(5)]
    result = sanitizer.sanitize_many(texts)

    assert result == texts
    assert len(sanitizer._analyzer.calls) == 6
    assert all(len(call[0]) <= 25 for call in sanitizer._analyzer.calls)
    assert [call[1] for call in sanitizer._analyzer.calls] == [
        "ru",
        "en",
        "ru",
        "en",
        "ru",
        "en",
    ]


def test_resource_envelope_is_sanitized_and_uri_is_removed(policy):
    result = policy.sanitize(
        "get_issue",
        {
            "contents": [
                {
                    "uri": "youtrack://issues/1-1",
                    "mimeType": "application/json",
                    "text": {
                        "idReadable": "DEMO-1",
                        "reporter": {"name": "Ivan Ivanov"},
                    },
                }
            ]
        },
    )

    assert result == {
        "contents": [{"mimeType": "application/json", "text": {"id": "DEMO-1"}}]
    }


def test_non_allowlisted_tool_is_rejected(policy):
    with pytest.raises(PolicyViolation):
        policy.sanitize("get_attachment_content", {"content_base64": "secret"})
