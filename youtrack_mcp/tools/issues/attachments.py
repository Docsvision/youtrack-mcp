"""
YouTrack Issue Attachments Module.

This module contains functions for handling issue attachments and raw data access:
- Raw issue data retrieval bypassing Pydantic models
- Attachment content access with base64 encoding
- Comprehensive attachment metadata retrieval
- File size analysis and format conversion

These functions enable file handling and detailed data access within YouTrack workflows.
"""

import json
import base64
import logging
from typing import Any, Dict

from youtrack_mcp.api.issues import AttachmentNotFoundError
from youtrack_mcp.config import Config
from youtrack_mcp.mcp_wrappers import sync_wrapper
from youtrack_mcp.utils import format_json_response

logger = logging.getLogger(__name__)

SAFE_RASTER_IMAGE_MIME_TYPES = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}
)


def _matches_image_signature(content: bytes, mime_type: str) -> bool:
    """Reject files whose bytes do not match their declared raster image type."""

    signatures = {
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/gif": content.startswith((b"GIF87a", b"GIF89a")),
        "image/webp": (
            len(content) >= 12
            and content.startswith(b"RIFF")
            and content[8:12] == b"WEBP"
        ),
        "image/bmp": content.startswith(b"BM"),
    }
    return signatures.get(mime_type, False)


class Attachments:
    """Issue attachment and raw data access functions."""

    def __init__(self, issues_api, projects_api):
        """Initialize with API clients."""
        self.issues_api = issues_api
        self.projects_api = projects_api
        self.client = issues_api.client  # Direct access for raw API calls

    @sync_wrapper
    def get_issue_raw(self, issue_id: str) -> str:
        """
        Get raw information about a specific issue, bypassing the Pydantic model.

        Args:
            issue_id: The issue identifier (e.g., "DEMO-123", "PROJECT-456")

        Returns:
            Raw JSON string with the issue data
        """
        try:
            # Request comprehensive fields for raw issue data
            fields = "id,idReadable,summary,description,created,updated,project(id,name,shortName),reporter(id,login,name),assignee(id,login,name),customFields(id,name,value(id,name)),attachments(id,name,size,url),comments(id,text,author(login,name),created)"
            raw_issue = self.client.get(f"issues/{issue_id}?fields={fields}")
            return format_json_response(raw_issue)
        except Exception as e:
            logger.exception(f"Error getting raw issue {issue_id}")
            return format_json_response({"error": str(e)})

    @sync_wrapper
    def get_attachment_content(self, issue_id: str, attachment_id: str) -> str:
        """
        Get the content of an attachment as a base64-encoded string.

        Args:
            issue_id: The issue identifier (e.g., "DEMO-123", "PROJECT-456")
            attachment_id: The attachment ID (e.g., "1-123")

        Returns:
            JSON string with the attachment content encoded in base64
        """
        try:
            content = self.issues_api.get_attachment_content(issue_id, attachment_id)
            encoded_content = base64.b64encode(content).decode("utf-8")

            # Get attachment metadata for additional info
            issue_response = self.client.get(
                f"issues/{issue_id}?fields=attachments(id,name,mimeType,size)"
            )
            attachment_metadata = None

            if "attachments" in issue_response:
                for attachment in issue_response["attachments"]:
                    if attachment.get("id") == attachment_id:
                        attachment_metadata = attachment
                        break

            return json.dumps(
                {
                    "content": encoded_content,
                    "size_bytes_original": len(content),
                    "size_bytes_base64": len(encoded_content),
                    "filename": (
                        attachment_metadata.get("name") if attachment_metadata else None
                    ),
                    "mime_type": (
                        attachment_metadata.get("mimeType")
                        if attachment_metadata
                        else None
                    ),
                    "size_increase_percent": (
                        round((len(encoded_content) / len(content) - 1) * 100, 1)
                        if len(content) > 0
                        else 0.0
                    ),
                    "status": "success",
                }
            )
        except Exception as e:
            logger.exception(
                f"Error getting attachment content for issue {issue_id}, attachment {attachment_id}"
            )
            return format_json_response({"error": str(e), "status": "error"})

    @sync_wrapper
    def get_issue_image(self, issue_id: str, attachment_id: str) -> str:
        """Get a safe raster image attachment from an explicitly allowed project."""

        try:
            fields = (
                "idReadable,project(shortName)," "attachments(id,name,mimeType,size)"
            )
            issue = self.client.get(f"issues/{issue_id}?fields={fields}")
            project = str((issue.get("project") or {}).get("shortName", "")).upper()
            if project not in Config.get_allowed_image_projects():
                raise ValueError(
                    f"Image attachments are not enabled for project '{project}'"
                )

            attachment = next(
                (
                    item
                    for item in issue.get("attachments", [])
                    if isinstance(item, dict) and item.get("id") == attachment_id
                ),
                None,
            )
            if attachment is None:
                raise ValueError(
                    f"Attachment {attachment_id} not found in issue {issue_id}"
                )

            mime_type = str(attachment.get("mimeType", "")).lower()
            if mime_type not in SAFE_RASTER_IMAGE_MIME_TYPES:
                raise ValueError(
                    f"Attachment {attachment_id} is not an allowed raster image"
                )

            content = self.issues_api.get_attachment_content(issue_id, attachment_id)
            if not _matches_image_signature(content, mime_type):
                raise ValueError(
                    f"Attachment {attachment_id} does not match its declared image type"
                )

            return json.dumps(
                {
                    "issue_id": issue.get("idReadable") or issue_id,
                    "project": project,
                    "attachment_id": attachment_id,
                    "filename": attachment.get("name"),
                    "mime_type": mime_type,
                    "size_bytes": len(content),
                    "content": base64.b64encode(content).decode("ascii"),
                    "status": "success",
                }
            )
        except Exception as e:
            logger.exception(
                "Error getting image attachment %s from issue %s",
                attachment_id,
                issue_id,
            )
            return format_json_response({"error": str(e), "status": "error"})

    @sync_wrapper
    def delete_attachment(self, issue_id: str, attachment_id: str) -> str:
        """
        Delete an attachment from an issue.

        Args:
            issue_id: The issue identifier (e.g., "DEMO-123", "PROJECT-456")
            attachment_id: The attachment ID to delete (e.g., "1-123")

        Returns:
            JSON string with the deletion status
        """
        try:
            self.issues_api.delete_attachment(issue_id, attachment_id)
            return format_json_response(
                {
                    "status": "success",
                    "message": f"Attachment {attachment_id} successfully deleted from issue {issue_id}",
                }
            )
        except AttachmentNotFoundError as e:
            logger.warning(f"Attachment not found: {e}")
            return format_json_response({"error": str(e), "status": "not_found"})
        except Exception as e:
            logger.exception(
                f"Error deleting attachment {attachment_id} from issue {issue_id}"
            )
            return format_json_response({"error": str(e), "status": "error"})

    def get_tool_definitions(self) -> Dict[str, Dict[str, Any]]:
        """Get tool definitions for attachment functions."""
        return {
            "get_issue_raw": {
                "description": "Get comprehensive raw issue data bypassing Pydantic models, including all fields, custom fields, attachments, and comments. Useful for detailed data analysis or when structured models are insufficient. Example: get_issue_raw(issue_id='DEMO-123')",
                "parameter_descriptions": {
                    "issue_id": "Issue identifier like 'DEMO-123' or 'PROJECT-456'"
                },
            },
            "get_attachment_content": {
                "description": "Download and retrieve attachment content as base64-encoded data with comprehensive metadata including file size analysis and format information. Supports files up to 5MB. Example: get_attachment_content(issue_id='DEMO-123', attachment_id='1-456')",
                "parameter_descriptions": {
                    "issue_id": "Issue identifier containing the attachment like 'DEMO-123'",
                    "attachment_id": "Attachment identifier from issue attachments list like '1-456' or '2-789'",
                },
            },
            "get_issue_image": {
                "description": "Get a raster image attachment from an issue in an explicitly allowed project. Only PNG, JPEG, GIF, WebP, and BMP images are accepted. Example: get_issue_image(issue_id='GBL-123', attachment_id='1-456')",
                "parameter_descriptions": {
                    "issue_id": "Issue identifier in an allowed project, such as 'GBL-123'",
                    "attachment_id": "Image attachment identifier returned by get_issue",
                },
            },
            "delete_attachment": {
                "description": "Delete an attachment from an issue. Requires appropriate permissions (either being the attachment author or having 'Delete Attachment' permission in the project). The deletion is permanent. Example: delete_attachment(issue_id='DEMO-123', attachment_id='1-456')",
                "parameter_descriptions": {
                    "issue_id": "Issue identifier containing the attachment like 'DEMO-123'",
                    "attachment_id": "Attachment identifier to delete from issue attachments list like '1-456' or '2-789'",
                },
            },
        }
