"""Fail-closed allowlist for operations which cannot mutate YouTrack."""

from __future__ import annotations

READ_ONLY_TOOLS = frozenset(
    {
        "advanced_search",
        "diagnose_workflow_restrictions",
        "download_article_attachment",
        "get_all_custom_fields_schemas",
        "get_all_issues",
        "get_all_projects",
        "get_all_users",
        "get_article",
        "get_attachment_content",
        "get_available_custom_field_values",
        "get_available_link_types",
        "get_current_user",
        "get_custom_field_allowed_values",
        "get_custom_field_schema",
        "get_custom_fields",
        "get_field_values",
        "get_help",
        "get_issue",
        "get_issue_comments",
        "get_issue_links",
        "get_issue_raw",
        "get_project",
        "get_project_by_name",
        "get_project_issues",
        "get_projects",
        "get_space",
        "get_user",
        "get_user_by_id",
        "get_user_permissions",
        "list_article_attachments",
        "list_article_comments",
        "list_articles",
        "list_resources",
        "list_spaces",
        "read_resource",
        "search_articles",
        "search_articles_filtered",
        "search_issues",
        "search_users",
        "search_with_custom_field_values",
        "search_with_filter",
        "validate_custom_field",
        "validate_custom_field_for_project",
    }
)


def is_read_only_tool(tool_name: str) -> bool:
    """Return whether a tool is explicitly approved as non-mutating."""

    normalized = tool_name.strip().lower().replace("-", "_")
    return normalized in READ_ONLY_TOOLS
