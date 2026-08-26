"""Tests for the useful-but-pseudonymized diagnostic output profile."""

from sanitizer_service.service import OutputPolicy, Pseudonymizer


class PassthroughTextSanitizer:
    def sanitize(self, text: str) -> str:
        return text


def make_policy():
    pseudonymizer = Pseudonymizer(b"deterministic-test-key")
    policy = OutputPolicy(
        PassthroughTextSanitizer(),
        profile="diagnostic",
        pseudonymizer=pseudonymizer,
    )
    return policy, pseudonymizer


def test_pseudonyms_are_stable_and_case_insensitive():
    pseudonymizer = Pseudonymizer(b"deterministic-test-key")

    assert pseudonymizer.alias("Ivan") == pseudonymizer.alias(" ivan ")
    assert pseudonymizer.alias("ivan") != pseudonymizer.alias("petr")
    assert pseudonymizer.alias("ivan").startswith("USER-")


def test_diagnostic_issue_retains_safe_fields_and_pseudonymizes_identities():
    policy, pseudonymizer = make_policy()

    result = policy.sanitize(
        "get_issue",
        {
            "idReadable": "DEMO-1",
            "summary": "Failure in version 6.1.0",
            "resolved": 123456,
            "reporter": {"login": "ivan", "fullName": "Ivan Ivanov"},
            "tags": [{"name": "regression"}],
            "custom_fields": [
                {"name": "State", "value": {"name": "Open", "id": "1"}},
                {"name": "Fix versions", "value": [{"name": "6.1.0"}]},
                {"name": "Assignee", "value": {"login": "petr", "name": "Petr"}},
                {"name": "Customer", "value": "must be retained"},
                {
                    "name": "Developer",
                    "$type": "SingleUserIssueCustomField",
                    "value": {"login": "olga", "name": "Olga"},
                },
            ],
        },
    )

    assert result == {
        "id": "DEMO-1",
        "summary": "Failure in version 6.1.0",
        "resolved": 123456,
        "reporter": pseudonymizer.alias("ivan"),
        "tags": ["regression"],
        "customFields": [
            {"name": "State", "value": {"name": "Open"}},
            {"name": "Fix versions", "value": [{"name": "6.1.0"}]},
            {"name": "Assignee", "value": pseudonymizer.alias("petr")},
            {"name": "Customer", "value": "must be retained"},
            {"name": "Developer", "value": pseudonymizer.alias("olga")},
        ],
    }


def test_diagnostic_issue_exposes_only_gbl_raster_attachment_metadata(monkeypatch):
    monkeypatch.setenv("SANITIZER_ALLOWED_IMAGE_PROJECTS", "GBL")
    policy, _ = make_policy()

    result = policy.sanitize(
        "get_issue",
        {
            "idReadable": "GBL-1",
            "project": {"shortName": "GBL", "name": "Global"},
            "attachments": [
                {
                    "id": "1-1",
                    "name": "screen.png",
                    "mimeType": "image/png",
                    "size": 123,
                },
                {
                    "id": "1-2",
                    "name": "spec.pdf",
                    "mimeType": "application/pdf",
                    "size": 456,
                },
            ],
        },
    )

    assert result["attachments"] == [
        {
            "id": "1-1",
            "name": "screen.png",
            "mimeType": "image/png",
            "size": 123,
        }
    ]


def test_comment_author_and_matching_mention_use_same_alias():
    policy, pseudonymizer = make_policy()

    result = policy.sanitize(
        "get_issue_comments",
        [{"text": "Ask @ivan for details", "author": {"login": "ivan"}}],
    )

    alias = pseudonymizer.alias("ivan")
    assert result == [{"text": f"Ask @{alias} for details", "author": alias}]


def test_link_groups_only_return_real_linked_issues():
    policy, _ = make_policy()

    result = policy.sanitize(
        "get_issue_links",
        [
            {
                "direction": "OUTWARD",
                "linkType": {
                    "name": "Depend",
                    "sourceToTarget": "depends on",
                    "targetToSource": "is required for",
                },
                "issues": [{"idReadable": "DEMO-2", "summary": "Dependency"}],
            },
            {"direction": "INWARD", "linkType": {"name": "Relates"}, "issues": []},
        ],
    )

    assert result == [
        {
            "direction": "OUTWARD",
            "type": "depends on",
            "issues": [{"id": "DEMO-2", "summary": "Dependency"}],
        }
    ]
