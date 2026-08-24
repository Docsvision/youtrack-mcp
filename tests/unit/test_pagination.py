"""Tests for shared YouTrack collection pagination."""

from unittest.mock import Mock, call

import pytest

from youtrack_mcp.api.pagination import get_all_pages


def test_get_all_pages_reads_until_short_page():
    client = Mock()
    client.get.side_effect = [[{"id": "1"}, {"id": "2"}], [{"id": "3"}]]

    result = get_all_pages(client, "items", fields="id", page_size=2)

    assert result == [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    assert client.get.call_args_list == [
        call("items", params={"fields": "id", "$top": 2, "$skip": 0}),
        call("items", params={"fields": "id", "$top": 2, "$skip": 2}),
    ]


def test_get_all_pages_checks_after_exact_page_boundary():
    client = Mock()
    client.get.side_effect = [[{"id": "1"}, {"id": "2"}], []]

    result = get_all_pages(client, "items", fields="id", page_size=2)

    assert len(result) == 2
    assert client.get.call_count == 2


def test_get_all_pages_rejects_non_collection_response():
    client = Mock()
    client.get.return_value = {"id": "not-a-list"}

    with pytest.raises(TypeError, match="returned a non-list"):
        get_all_pages(client, "items", fields="id")


def test_get_all_pages_rejects_invalid_page_size():
    with pytest.raises(ValueError, match="positive"):
        get_all_pages(Mock(), "items", fields="id", page_size=0)
