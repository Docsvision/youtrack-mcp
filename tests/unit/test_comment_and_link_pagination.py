"""Integration tests for complete comment and linked-issue retrieval."""

import json
from unittest.mock import Mock

from youtrack_mcp.api.issues import IssuesClient
from youtrack_mcp.tools.resources import ResourcesTools


def test_get_issue_comments_combines_all_pages():
    client = Mock()
    first_page = [{"id": f"comment-{index}", "text": str(index)} for index in range(42)]
    client.get.side_effect = [first_page, [{"id": "comment-42", "text": "42"}]]
    tools = ResourcesTools.__new__(ResourcesTools)
    tools.client = client

    result = json.loads(tools.get_issue_comments("DEMO-1"))
    comments = json.loads(result["contents"][0]["text"])

    assert len(comments) == 43
    assert comments[-1]["id"] == "comment-42"
    assert client.get.call_args_list[0].kwargs["params"]["$skip"] == 0
    assert client.get.call_args_list[1].kwargs["params"]["$skip"] == 42


def test_get_issue_links_paginates_issues_inside_each_link_group():
    client = Mock()
    first_issue_page = [
        {
            "id": f"internal-{index}",
            "idReadable": f"DEMO-{index}",
            "summary": str(index),
        }
        for index in range(42)
    ]
    client.get.side_effect = [
        [{"id": "link-1", "direction": "OUTWARD", "linkType": {"name": "Depend"}}],
        first_issue_page,
        [{"id": "internal-42", "idReadable": "DEMO-42", "summary": "42"}],
    ]

    result = IssuesClient(client).get_issue_links("DEMO-1")

    assert len(result) == 1
    assert len(result[0]["issues"]) == 43
    assert result[0]["issues"][-1]["idReadable"] == "DEMO-42"
    assert client.get.call_args_list[1].args[0] == "issues/DEMO-1/links/link-1/issues"
    assert client.get.call_args_list[2].kwargs["params"]["$skip"] == 42
