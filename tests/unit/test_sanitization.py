"""Tests for the central MCP output-sanitization boundary."""

import json

import pytest

from youtrack_mcp.mcp_wrappers import create_bound_tool
from youtrack_mcp.sanitization import OutputSanitizationBoundary, SanitizationError


class RecordingSanitizer:
    def __init__(self, replacement):
        self.replacement = replacement
        self.calls = []

    def sanitize(self, tool_name, payload):
        self.calls.append((tool_name, payload))
        return self.replacement


@pytest.mark.unit
def test_boundary_parses_and_restores_json_string_results():
    backend = RecordingSanitizer({"id": "DEMO-1", "reporter": "USER-1"})
    boundary = OutputSanitizationBoundary(backend)

    result = boundary.sanitize(
        "get_issue",
        json.dumps({"id": "DEMO-1", "reporter": "Ivan Ivanov"}),
    )

    assert json.loads(result) == {"id": "DEMO-1", "reporter": "USER-1"}
    assert backend.calls == [("get_issue", {"id": "DEMO-1", "reporter": "Ivan Ivanov"})]


@pytest.mark.unit
def test_boundary_exposes_nested_resource_json_to_backend():
    resource_result = json.dumps(
        {
            "contents": [
                {
                    "mimeType": "application/json",
                    "text": json.dumps({"id": "DEMO-1", "reporter": "Ivan Ivanov"}),
                }
            ]
        }
    )
    sanitized_resource = {
        "contents": [{"mimeType": "application/json", "text": {"id": "DEMO-1"}}]
    }
    backend = RecordingSanitizer(sanitized_resource)
    boundary = OutputSanitizationBoundary(backend)

    result = json.loads(boundary.sanitize("get_issue", resource_result))

    assert json.loads(result["contents"][0]["text"]) == {"id": "DEMO-1"}
    assert backend.calls[0][1]["contents"][0]["text"] == {
        "id": "DEMO-1",
        "reporter": "Ivan Ivanov",
    }


@pytest.mark.unit
def test_boundary_sanitizes_plain_text_without_changing_its_type():
    backend = RecordingSanitizer("Contact [PERSON]")
    boundary = OutputSanitizationBoundary(backend)

    assert boundary.sanitize("get_help", "Contact Ivan") == "Contact [PERSON]"


@pytest.mark.unit
def test_boundary_fails_closed():
    class FailingSanitizer:
        def sanitize(self, tool_name, payload):
            raise RuntimeError("backend unavailable")

    boundary = OutputSanitizationBoundary(FailingSanitizer(), fail_closed=True)

    with pytest.raises(SanitizationError):
        boundary.sanitize("get_issue", {"description": "sensitive"})


@pytest.mark.unit
def test_every_bound_tool_uses_the_central_boundary(monkeypatch):
    backend = RecordingSanitizer({"safe": True})
    boundary = OutputSanitizationBoundary(backend)
    monkeypatch.setattr(
        "youtrack_mcp.sanitization.get_output_sanitization_boundary",
        lambda: boundary,
    )

    class TestTools:
        def get_issue(self, issue_id):
            return {"id": issue_id, "reporter": "Ivan Ivanov"}

    result = create_bound_tool(TestTools(), "get_issue")(issue_id="DEMO-1")

    assert result == {"safe": True}
    assert backend.calls == [("get_issue", {"id": "DEMO-1", "reporter": "Ivan Ivanov"})]
