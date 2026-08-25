from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from youtrack_mcp.api.client import YouTrackClient


class Article(BaseModel):
    """Model for a YouTrack Knowledge Base Article."""

    id: str
    idReadable: Optional[str] = None
    summary: Optional[str] = None
    content: Optional[str] = None
    created: Optional[int] = None
    updated: Optional[int] = None
    project: Optional[Dict[str, Any]] = None

    model_config = {
        "extra": "allow",
        "populate_by_name": True,
    }


class Comment(BaseModel):
    """Model for a Knowledge Base Article Comment."""

    id: str
    text: Optional[str] = None
    updated: Optional[int] = None
    author: Optional[Dict[str, Any]] = None

    model_config = {
        "extra": "allow",
        "populate_by_name": True,
    }


class Attachment(BaseModel):
    """Model for a Knowledge Base Article Attachment."""

    id: str
    name: Optional[str] = None
    mimeType: Optional[str] = None
    size: Optional[int] = None

    model_config = {
        "extra": "allow",
        "populate_by_name": True,
    }


class ArticlesClient:
    """Client for interacting with YouTrack Articles API."""

    def __init__(self, client: YouTrackClient):
        self.client = client

    def get_article(self, article_id: str, fields: Optional[str] = None) -> Article:
        """
        Get a single article by id.

        Args:
            article_id: The internal article id (e.g., "1-23")
            fields: Optional fields selection string

        Returns:
            Article model
        """
        fields_query = fields or (
            "id,idReadable,summary,content,created,updated,"
            "project(id,name,shortName)"
        )
        response = self.client.get(
            f"articles/{article_id}", params={"fields": fields_query}
        )
        return Article.model_validate(response)

    def list_articles(
        self,
        project_id: Optional[str] = None,
        fields: Optional[str] = None,
        top: int = 20,
        skip: int = 0,
    ) -> List[Article]:
        """
        List articles, optionally restricted to one YouTrack project.

        Args:
            project_id: Optional YouTrack project database ID
            fields: Optional fields selection string
            top: Max number of results to return
            skip: Offset for pagination

        Returns:
            List of Article models
        """
        params: Dict[str, Any] = {
            "$top": top,
            "$skip": skip,
            "fields": fields
            or "id,idReadable,summary,updated,project(id,name,shortName)",
        }

        endpoint = f"admin/projects/{project_id}/articles" if project_id else "articles"
        response = self.client.get(endpoint, params=params)

        # API may return list[dict]
        return [Article.model_validate(item) for item in response]

    def search_articles(
        self,
        query: str,
        fields: Optional[str] = None,
        top: int = 20,
        skip: int = 0,
        project_id: Optional[str] = None,
    ) -> List[Article]:
        """
        Search accessible article titles and content locally.

        The public YouTrack ``/api/articles`` collection has no search parameter,
        so the server pages through the REST collection and applies a Unicode-aware,
        case-insensitive word match. Pagination is applied to matching articles.
        """
        terms = [term for term in query.casefold().split() if term]
        if not terms or top <= 0 or skip < 0:
            return []

        requested_fields = (
            fields or "id,idReadable,summary,updated,project(id,name,shortName)"
        )
        search_fields = (
            "id,idReadable,summary,content,created,updated,"
            "project(id,name,shortName)"
        )
        endpoint = f"admin/projects/{project_id}/articles" if project_id else "articles"
        page_size = 42
        api_skip = 0
        matching: List[Article] = []

        while len(matching) < skip + top:
            response = self.client.get(
                endpoint,
                params={
                    "$top": page_size,
                    "$skip": api_skip,
                    "fields": search_fields,
                },
            )
            page = [Article.model_validate(item) for item in response]
            if not page:
                break

            for article in page:
                project = article.project or {}
                haystack = "\n".join(
                    str(value)
                    for value in (
                        article.idReadable,
                        article.summary,
                        article.content,
                        project.get("name"),
                        project.get("shortName"),
                    )
                    if value
                ).casefold()
                if all(term in haystack for term in terms):
                    matching.append(article)
                    if len(matching) >= skip + top:
                        break

            api_skip += len(page)
            if len(page) < page_size:
                break

        include_content = "content" in requested_fields
        result = matching[skip : skip + top]
        if not include_content:
            for article in result:
                article.content = None
        return result

    def search_articles_filtered(
        self,
        space_id: Optional[str] = None,
        author: Optional[str] = None,
        tag: Optional[str] = None,
        status: Optional[str] = None,  # e.g., 'draft' or 'published'
        updated_since: Optional[str] = None,  # ISO8601 or epoch millis string
        sort: Optional[str] = None,  # e.g., 'updated desc'
        query: Optional[str] = None,
        fields: Optional[str] = None,
        top: int = 20,
        skip: int = 0,
    ) -> List[Article]:
        """
        Search articles with rich filters.
        """
        params: Dict[str, Any] = {
            "$top": top,
            "$skip": skip,
            "fields": fields or "id,summary,updated,space(id,name)",
        }

        parts: List[str] = []
        if space_id:
            parts.append(f"space:{space_id}")
        if author:
            parts.append(f"author:{author}")
        if tag:
            parts.append(f"tag:{tag}")
        if status:
            parts.append(f"status:{status}")
        if updated_since:
            parts.append(f"updated:{updated_since}..")
        if query:
            parts.append(query)

        if parts:
            params["query"] = " ".join(parts)
        if sort:
            params["sort"] = sort

        response = self.client.get("articles", params=params)
        return [Article.model_validate(item) for item in response]

    # === Create / Update / Status ===
    def create_article(
        self,
        space_id: str,
        summary: str,
        content: str,
        parent_article_id: Optional[str] = None,
        status: Optional[str] = None,
        fields: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Article:
        """
        Create a new Knowledge Base article.
        """
        payload: Dict[str, Any] = {
            "space": {"id": space_id},
            "summary": summary,
            "content": content,
        }
        if parent_article_id:
            payload["parentArticle"] = {"id": parent_article_id}
        if status:
            payload["status"] = status
        if extra:
            payload.update(extra)

        endpoint = "articles"
        if fields:
            endpoint = f"articles?fields={fields}"
        response = self.client.post(endpoint, json_data=payload)
        return Article.model_validate(response)

    def update_article(
        self,
        article_id: str,
        summary: Optional[str] = None,
        content: Optional[str] = None,
        space_id: Optional[str] = None,
        parent_article_id: Optional[str] = None,
        status: Optional[str] = None,
        fields: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Article:
        """
        Update an existing article. Only provided fields are changed.
        """
        payload: Dict[str, Any] = {}
        if summary is not None:
            payload["summary"] = summary
        if content is not None:
            payload["content"] = content
        if space_id is not None:
            payload["space"] = {"id": space_id}
        if parent_article_id is not None:
            payload["parentArticle"] = {"id": parent_article_id}
        if status is not None:
            payload["status"] = status
        if extra:
            payload.update(extra)

        endpoint = f"articles/{article_id}"
        if fields:
            endpoint = f"articles/{article_id}?fields={fields}"
        response = self.client.post(endpoint, json_data=payload)
        return Article.model_validate(response)

    def set_article_status(self, article_id: str, status: str) -> Article:
        """Convenience to set article status (e.g., 'draft', 'published')."""
        return self.update_article(article_id, status=status)

    # === Comments ===
    def list_article_comments(
        self,
        article_id: str,
        fields: Optional[str] = None,
        top: int = 50,
        skip: int = 0,
    ) -> List[Comment]:
        params: Dict[str, Any] = {
            "$top": top,
            "$skip": skip,
            "fields": fields or "id,text,updated,author(login,name)",
        }
        response = self.client.get(f"articles/{article_id}/comments", params=params)
        return [Comment.model_validate(item) for item in response]

    def add_article_comment(
        self, article_id: str, text: str, fields: Optional[str] = None
    ) -> Comment:
        endpoint = f"articles/{article_id}/comments"
        if fields:
            endpoint = f"articles/{article_id}/comments?fields={fields}"
        response = self.client.post(endpoint, json_data={"text": text})
        return Comment.model_validate(response)

    def update_article_comment(
        self, article_id: str, comment_id: str, text: str, fields: Optional[str] = None
    ) -> Comment:
        endpoint = f"articles/{article_id}/comments/{comment_id}"
        if fields:
            endpoint = f"articles/{article_id}/comments/{comment_id}?fields={fields}"
        response = self.client.post(endpoint, json_data={"text": text})
        return Comment.model_validate(response)

    # === Attachments ===
    def list_article_attachments(
        self,
        article_id: str,
        fields: Optional[str] = None,
        top: int = 50,
        skip: int = 0,
    ) -> List[Attachment]:
        params: Dict[str, Any] = {
            "$top": top,
            "$skip": skip,
            "fields": fields or "id,name,mimeType,size",
        }
        response = self.client.get(f"articles/{article_id}/attachments", params=params)
        return [Attachment.model_validate(item) for item in response]

    def upload_article_attachment(
        self,
        article_id: str,
        filename: str,
        file_bytes: bytes,
        mime_type: str = "application/octet-stream",
        fields: Optional[str] = None,
    ) -> Attachment:
        endpoint = f"articles/{article_id}/attachments"
        if fields:
            endpoint = f"articles/{article_id}/attachments?fields={fields}"
        files = {"file": (filename, file_bytes, mime_type)}
        response = self.client.post_multipart(endpoint, files=files)
        return Attachment.model_validate(response)

    def download_article_attachment(self, article_id: str, attachment_id: str) -> bytes:
        endpoint = f"articles/{article_id}/attachments/{attachment_id}/content"
        return self.client.get_bytes(
            endpoint, headers={"Accept": "application/octet-stream"}
        )
