"""Unit tests for structural output policies without loading NLP models."""

import pytest

from sanitizer_service.service import OutputPolicy, PolicyViolation


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
