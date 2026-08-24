"""Shared pagination helpers for YouTrack collection resources."""

from typing import Any

from youtrack_mcp.api.client import YouTrackClient

DEFAULT_PAGE_SIZE = 42


def get_all_pages(
    client: YouTrackClient,
    endpoint: str,
    *,
    fields: str,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> list[Any]:
    """Read every page from a YouTrack collection endpoint."""
    if page_size <= 0:
        raise ValueError("page_size must be positive")

    items: list[Any] = []
    skip = 0

    while True:
        page = client.get(
            endpoint,
            params={"fields": fields, "$top": page_size, "$skip": skip},
        )
        if not isinstance(page, list):
            raise TypeError(f"YouTrack collection '{endpoint}' returned a non-list")

        items.extend(page)
        if len(page) < page_size:
            return items

        skip += len(page)
