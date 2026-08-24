"""Strict profile must not retain login-derived aliases."""

from sanitizer_service.service import OutputPolicy, Pseudonymizer


class PassthroughTextSanitizer:
    def sanitize(self, text: str) -> str:
        return text


def test_strict_profile_removes_mentions_instead_of_pseudonymizing():
    policy = OutputPolicy(
        PassthroughTextSanitizer(),
        profile="strict",
        pseudonymizer=Pseudonymizer(b"test-key"),
    )

    result = policy.sanitize(
        "get_issue_comments",
        [{"text": "Ask @ivan", "author": {"login": "ivan"}}],
    )

    assert result == [{"text": "Ask [USER]"}]
