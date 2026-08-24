"""Regression test for requesting actual issues in YouTrack link groups."""

from unittest.mock import Mock

from youtrack_mcp.api.issues import IssuesClient


def test_get_issue_links_requests_linked_issue_details():
    client = Mock()
    client.get.return_value = []

    result = IssuesClient(client).get_issue_links("DEMO-1")

    assert result == []
    request_path = client.get.call_args.args[0]
    params = client.get.call_args.kwargs["params"]
    assert request_path == "issues/DEMO-1/links"
    assert "sourceToTarget" in params["fields"]
    assert "targetToSource" in params["fields"]
    assert params["$top"] == 42
