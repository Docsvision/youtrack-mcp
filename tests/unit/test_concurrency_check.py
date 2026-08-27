"""Tests for the reusable MCP concurrency check."""

from scripts.check_mcp_concurrency import contains_tool_error


def test_detects_fail_closed_error_returned_as_json_text():
    body = {
        "isError": False,
        "content": [
            {
                "type": "text",
                "text": '{"status":"error","error":"Error calling get_issue"}',
            }
        ],
    }

    assert contains_tool_error(body)


def test_accepts_successful_json_text():
    body = {
        "isError": False,
        "content": [
            {"type": "text", "text": '{"status":"success","id":"SUP-1"}'}
        ],
    }

    assert not contains_tool_error(body)
