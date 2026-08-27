"""Presidio and detect-secrets based sanitization service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from copy import copy
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class PolicyViolation(ValueError):
    """Raised when a tool or payload is not permitted by the output policy."""


class TextSanitizer(Protocol):
    def sanitize(self, text: str) -> str:
        """Return text with secrets and PII removed."""


class PresidioAndSecretsSanitizer:
    """Ready-made PII and secret detection engines composed into one pipeline."""

    def __init__(self) -> None:
        try:
            from detect_secrets.core.scan import scan_line
            from detect_secrets.settings import default_settings
            from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
            from presidio_analyzer.nlp_engine import (
                NerModelConfiguration,
                StanzaNlpEngine,
            )
            from presidio_anonymizer import AnonymizerEngine
            from presidio_anonymizer.entities import OperatorConfig
        except ImportError as exc:
            raise RuntimeError("sanitizer dependencies are not installed") from exc

        models = [
            {"lang_code": "en", "model_name": "en"},
            {"lang_code": "ru", "model_name": "ru"},
        ]
        ner_configuration = {
            "model_to_presidio_entity_mapping": {
                "PER": "PERSON",
                "PERSON": "PERSON",
                "LOC": "LOCATION",
                "GPE": "LOCATION",
                "ORG": "ORGANIZATION",
            }
        }
        nlp_engine = StanzaNlpEngine(
            models=models,
            ner_model_configuration=NerModelConfiguration.from_dict(ner_configuration),
            download_if_missing=False,
        )
        nlp_engine.load()
        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en", "ru"],
        )
        recognizers = (
            (
                "INTERNAL_ID",
                r"(?i)(?<![0-9a-f])\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?(?![0-9a-f])",
                0.85,
            ),
            (
                "DATABASE",
                r"(?i)\b(?:[a-z][a-z0-9]*_)+(?:db|database)(?:_[a-z0-9]+)*\b|\b(?:db|database)(?:_[a-z0-9]+)+\b",
                0.75,
            ),
            (
                "INTERNAL_HOST",
                r"(?i)\b(?:app|web|wf|srv|server|node|host)[-_]?\d{1,4}\b",
                0.7,
            ),
            (
                "INTERNAL_PATH",
                r"\\\\[a-z0-9._-]+\\[^\r\n\t<>|\"]+",
                0.8,
            ),
        )
        for language in ("en", "ru"):
            for entity, expression, score in recognizers:
                self._analyzer.registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity=entity,
                        patterns=[Pattern(entity, expression, score)],
                        supported_language=language,
                    )
                )
        self._anonymizer = AnonymizerEngine()
        self._operator_config = OperatorConfig
        self._scan_line = scan_line
        self._secret_settings = default_settings
        self._score_threshold = float(os.getenv("SANITIZER_PII_SCORE_THRESHOLD", "0.4"))
        self._batch_max_chars = max(
            1, int(os.getenv("SANITIZER_PII_BATCH_MAX_CHARS", "4000"))
        )

    def _redact_secrets(self, text: str) -> str:
        values: set[str] = set()
        with self._secret_settings():
            for line in text.splitlines():
                for secret in self._scan_line(line):
                    value = getattr(secret, "secret_value", None)
                    if value and secret.type not in {
                        "Base64 High Entropy String",
                        "Hex High Entropy String",
                    }:
                        values.add(value)

        for value in sorted(values, key=len, reverse=True):
            text = text.replace(value, "[SECRET]")
        return text

    def _analyze_pii(self, text: str) -> list[Any]:
        results = []
        # Russian finds named entities. English also runs the standard Presidio
        # recognizers for language-independent patterns such as email and IP.
        for language in ("ru", "en"):
            results.extend(
                self._analyzer.analyze(
                    text=text,
                    language=language,
                    score_threshold=self._score_threshold,
                )
            )

        return results

    def _anonymize_pii(self, text: str, results: list[Any]) -> str:
        unique_results = list(
            {
                (item.start, item.end, item.entity_type): item
                for item in results
                if item.entity_type != "DATE_TIME"
            }.values()
        )
        if not unique_results:
            return text

        operators = {
            item.entity_type: self._operator_config(
                "replace", {"new_value": f"[{item.entity_type}]"}
            )
            for item in unique_results
        }
        return self._anonymizer.anonymize(
            text=text,
            analyzer_results=list(unique_results),
            operators=operators,
        ).text

    def _redact_pii(self, text: str) -> str:
        return self._anonymize_pii(text, self._analyze_pii(text))

    def _redact_pii_batch(self, texts: list[str]) -> list[str]:
        """Analyze one size-bounded collection with two NLP passes."""
        separator = "\n\n"
        offsets: list[tuple[int, int]] = []
        parts = []
        offset = 0
        for text in texts:
            parts.append(text)
            offsets.append((offset, offset + len(text)))
            offset += len(text) + len(separator)

        combined = separator.join(parts)
        try:
            combined_results = self._analyze_pii(combined)
        except ValueError:
            # Presidio's context enhancer can fail to align a recognizer match
            # with tokens in a synthetic, joined multilingual document. Retry
            # the original values independently; a repeated failure still
            # propagates and preserves fail-closed behavior.
            logger.warning(
                "Batch PII analysis failed; retrying %d values individually",
                len(texts),
                exc_info=True,
            )
            return [self._redact_pii(text) for text in texts]
        sanitized = []
        for text, (start, end) in zip(texts, offsets):
            local_results = []
            for result in combined_results:
                if result.start < start or result.end > end:
                    continue
                local_result = copy(result)
                local_result.start -= start
                local_result.end -= start
                local_results.append(local_result)
            sanitized.append(self._anonymize_pii(text, local_results))
        return sanitized

    def _redact_pii_many(self, texts: list[str]) -> list[str]:
        """Analyze a collection in bounded batches to avoid nonlinear NLP cost."""
        if not texts:
            return []

        separator_length = 2
        max_chars = getattr(self, "_batch_max_chars", 4000)
        sanitized: list[str] = []
        batch: list[str] = []
        batch_chars = 0

        for text in texts:
            added_chars = len(text) + (separator_length if batch else 0)
            if batch and batch_chars + added_chars > max_chars:
                sanitized.extend(self._redact_pii_batch(batch))
                batch = []
                batch_chars = 0
                added_chars = len(text)

            batch.append(text)
            batch_chars += added_chars

        if batch:
            sanitized.extend(self._redact_pii_batch(batch))
        return sanitized

    def sanitize(self, text: str) -> str:
        return self._redact_pii(self._redact_secrets(text))

    def sanitize_many(self, texts: list[str]) -> list[str]:
        secret_safe = [self._redact_secrets(text) for text in texts]
        return self._redact_pii_many(secret_safe)


class Pseudonymizer:
    """Create non-reversible aliases, stable for a configured deployment key."""

    def __init__(self, key: str | bytes | None = None) -> None:
        configured_key = key
        if configured_key is None:
            key_file = os.getenv("SANITIZER_PSEUDONYM_KEY_FILE")
            if key_file:
                try:
                    configured_key = Path(key_file).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise ValueError(
                        "SANITIZER_PSEUDONYM_KEY_FILE cannot be read"
                    ) from exc
                if not configured_key:
                    raise ValueError("SANITIZER_PSEUDONYM_KEY_FILE is empty")
            else:
                configured_key = os.getenv("SANITIZER_PSEUDONYM_KEY")
        if configured_key is None:
            logger.warning(
                "No sanitizer pseudonym key is set; aliases change after restart"
            )
            self._key = secrets.token_bytes(32)
        elif isinstance(configured_key, str):
            self._key = configured_key.encode("utf-8")
        else:
            self._key = configured_key

    def alias(self, value: Any, prefix: str = "USER") -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().casefold()
        if not normalized:
            return None
        digest = hmac.new(
            self._key, normalized.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:10]
        return f"{prefix}-{digest}"


TOOL_POLICIES = {
    "get_issue": "issue",
    "get_issue_image": "issue_image",
    "search_issues": "issues",
    "get_project_issues": "issues",
    "get_all_issues": "issues",
    "get_issue_comments": "comments",
    "get_issue_links": "links",
    "get_projects": "projects",
    "get_all_projects": "projects",
    "get_project": "project",
    "get_article": "article",
    "list_articles": "articles",
    "search_articles": "articles",
}


class OutputPolicy:
    """Strict structural allowlist followed by recursive text sanitization."""

    def __init__(
        self,
        text_sanitizer: TextSanitizer,
        profile: str | None = None,
        pseudonymizer: Pseudonymizer | None = None,
    ) -> None:
        self._text_sanitizer = text_sanitizer
        self._profile = (
            profile or os.getenv("SANITIZER_PROFILE", "diagnostic")
        ).lower()
        if self._profile not in {"strict", "diagnostic"}:
            raise ValueError("SANITIZER_PROFILE must be 'strict' or 'diagnostic'")
        self._pseudonymizer = pseudonymizer or Pseudonymizer()
        configured_fields = os.getenv("SANITIZER_ALLOWED_CUSTOM_FIELDS", "").strip()
        self._custom_fields = (
            {item.strip() for item in configured_fields.split(",") if item.strip()}
            if configured_fields and configured_fields != "*"
            else None
        )
        self._image_projects = {
            name.strip().upper()
            for name in os.getenv("SANITIZER_ALLOWED_IMAGE_PROJECTS", "").split(",")
            if name.strip()
        }

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        policy = TOOL_POLICIES.get(tool_name)
        if policy is None:
            raise PolicyViolation(f"tool '{tool_name}' is not allowlisted")
        if isinstance(payload, dict) and "contents" in payload:
            return self._resource_envelope(tool_name, payload)
        if isinstance(payload, dict) and "error" in payload:
            return {"status": "error", "error": "YouTrack request failed"}
        return getattr(self, f"_{policy}")(payload)

    def _prepare_text(self, value: str) -> str:
        return re.sub(
            r"(?<!\w)@([A-Za-z0-9][A-Za-z0-9._-]{1,63})",
            lambda match: (
                "@" + (self._pseudonymizer.alias(match.group(1)) or "USER")
                if self._profile == "diagnostic"
                else "[USER]"
            ),
            value,
        )

    def _texts(self, values: list[str]) -> list[str]:
        prepared = [self._prepare_text(value) for value in values]
        sanitize_many = getattr(self._text_sanitizer, "sanitize_many", None)
        if callable(sanitize_many):
            sanitized = sanitize_many(prepared)
            if len(sanitized) != len(prepared):
                raise ValueError("batch sanitizer returned an invalid result length")
            return sanitized
        return [self._text_sanitizer.sanitize(value) for value in prepared]

    def _text(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._texts([value])[0]
        if isinstance(value, list):
            return [self._text(item) for item in value]
        if isinstance(value, dict):
            return {key: self._text(item) for key, item in value.items()}
        return value

    def _resource_envelope(self, tool_name: str, payload: dict[str, Any]) -> dict:
        contents = payload.get("contents")
        if not isinstance(contents, list):
            raise PolicyViolation("resource contents must be a list")
        safe_contents = []
        for content in contents:
            if not isinstance(content, dict) or "text" not in content:
                raise PolicyViolation("invalid resource content")
            safe_contents.append(
                {
                    "mimeType": "application/json",
                    "text": self.sanitize(tool_name, content["text"]),
                }
            )
        return {"contents": safe_contents}

    def _project_value(self, value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        return {
            key: self._text(value[key]) for key in ("shortName", "name") if key in value
        }

    def _identity(self, value: Any) -> str | None:
        if self._profile != "diagnostic" or not isinstance(value, dict):
            return None
        identity = next(
            (
                value.get(key)
                for key in ("login", "id", "fullName", "name")
                if value.get(key)
            ),
            None,
        )
        return self._pseudonymizer.alias(identity)

    def _custom_field_value(self, value: Any, identity: bool = False) -> Any:
        if isinstance(value, dict):
            if identity:
                return self._identity(value)
            return {
                key: self._custom_field_value(item, identity=identity)
                for key, item in value.items()
                if key in {"name", "text", "presentation"}
            }
        if isinstance(value, list):
            return [self._custom_field_value(item, identity=identity) for item in value]
        return self._text(value)

    def _issue(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PolicyViolation("issue payload must be an object")
        safe: dict[str, Any] = {}
        readable_id = payload.get("idReadable") or payload.get("id")
        if readable_id is not None:
            safe["id"] = readable_id
        for key in ("summary", "description"):
            if key in payload:
                safe[key] = self._text(payload[key])
        for key in (
            "created",
            "updated",
            "resolved",
            "created_iso8601",
            "updated_iso8601",
        ):
            if key in payload:
                safe[key] = payload[key]
        project = self._project_value(payload.get("project"))
        if project:
            safe["project"] = project
        if self._profile == "diagnostic":
            for key in ("reporter", "updater", "assignee"):
                alias = self._identity(payload.get(key))
                if alias:
                    safe[key] = alias
            tags = payload.get("tags")
            if isinstance(tags, list):
                safe["tags"] = [
                    self._text(tag.get("name"))
                    for tag in tags
                    if isinstance(tag, dict) and tag.get("name")
                ]
        custom_fields = []
        for field in payload.get("customFields") or payload.get("custom_fields") or []:
            if (
                not isinstance(field, dict)
                or not field.get("name")
                or (
                    self._custom_fields is not None
                    and field["name"] not in self._custom_fields
                )
            ):
                continue
            field_type = str(field.get("$type", ""))
            custom_fields.append(
                {
                    "name": field["name"],
                    "value": self._custom_field_value(
                        field.get("value"),
                        identity=(
                            field["name"] == "Assignee"
                            or "UserIssueCustomField" in field_type
                        ),
                    ),
                }
            )
        if custom_fields:
            safe["customFields"] = custom_fields
        project_short_name = str(
            (payload.get("project") or {}).get("shortName", "")
            if isinstance(payload.get("project"), dict)
            else ""
        ).upper()
        if project_short_name in self._image_projects:
            attachments = []
            for attachment in payload.get("attachments") or []:
                if not isinstance(attachment, dict):
                    continue
                mime_type = str(attachment.get("mimeType", "")).lower()
                if mime_type not in {
                    "image/png",
                    "image/jpeg",
                    "image/gif",
                    "image/webp",
                    "image/bmp",
                }:
                    continue
                attachments.append(
                    {
                        key: (
                            self._text(attachment[key])
                            if key == "name"
                            else attachment[key]
                        )
                        for key in ("id", "name", "mimeType", "size")
                        if key in attachment
                    }
                )
            if attachments:
                safe["attachments"] = attachments
        return safe

    def _issue_image(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PolicyViolation("image payload must be an object")

        project = str(payload.get("project", "")).upper()
        if project not in self._image_projects:
            raise PolicyViolation("image project is not allowlisted")

        mime_type = str(payload.get("mime_type", "")).lower()
        content = payload.get("content")
        if mime_type not in {
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/bmp",
        } or not isinstance(content, str):
            raise PolicyViolation("attachment is not an allowed raster image")

        try:
            image_bytes = base64.b64decode(content, validate=True)
        except (ValueError, TypeError) as exc:
            raise PolicyViolation("image content is not valid base64") from exc
        if len(image_bytes) > 5 * 1024 * 1024:
            raise PolicyViolation("image exceeds the maximum allowed size")

        signatures = {
            "image/png": image_bytes.startswith(b"\x89PNG\r\n\x1a\n"),
            "image/jpeg": image_bytes.startswith(b"\xff\xd8\xff"),
            "image/gif": image_bytes.startswith((b"GIF87a", b"GIF89a")),
            "image/webp": (
                len(image_bytes) >= 12
                and image_bytes.startswith(b"RIFF")
                and image_bytes[8:12] == b"WEBP"
            ),
            "image/bmp": image_bytes.startswith(b"BM"),
        }
        if not signatures[mime_type]:
            raise PolicyViolation("image content does not match its MIME type")

        return {
            "issue_id": payload.get("issue_id"),
            "project": project,
            "attachment_id": payload.get("attachment_id"),
            "filename": self._text(payload.get("filename")),
            "mime_type": mime_type,
            "size_bytes": len(image_bytes),
            "content": content,
            "status": "success",
        }

    def _issues(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            raise PolicyViolation("issues payload must be a list")
        return [self._issue(item) for item in payload]

    def _comments(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            raise PolicyViolation("comments payload must be a list")
        safe = []
        text_targets: list[tuple[dict[str, Any], str]] = []
        for comment in payload:
            if not isinstance(comment, dict):
                raise PolicyViolation("comment payload must be an object")
            item = {
                key: comment[key] for key in ("created", "updated") if key in comment
            }
            if "text" in comment:
                if isinstance(comment["text"], str):
                    text_targets.append((item, comment["text"]))
                else:
                    item["text"] = self._text(comment["text"])
            author = self._identity(comment.get("author"))
            if author:
                item["author"] = author
            safe.append(item)

        sanitized_texts = self._texts([text for _, text in text_targets])
        for (item, _), text in zip(text_targets, sanitized_texts):
            item["text"] = text
        return safe

    def _links(self, payload: Any) -> Any:
        links = payload.get("links") if isinstance(payload, dict) else payload
        if not isinstance(links, list):
            raise PolicyViolation("links payload must be a list")
        safe = []
        for link in links:
            if not isinstance(link, dict):
                raise PolicyViolation("link payload must be an object")
            linked_issues = link.get("issues")
            if isinstance(linked_issues, list):
                safe_issues = [
                    self._issue(issue)
                    for issue in linked_issues
                    if isinstance(issue, dict)
                ]
                if not safe_issues:
                    continue
                item: dict[str, Any] = {"issues": safe_issues}
                if "direction" in link:
                    item["direction"] = self._text(link["direction"])
                link_type = link.get("linkType")
                if isinstance(link_type, dict):
                    direction = str(link.get("direction", "")).upper()
                    preferred = (
                        "sourceToTarget" if direction == "OUTWARD" else "targetToSource"
                    )
                    label = link_type.get(preferred) or link_type.get("name")
                    if label:
                        item["type"] = self._text(label)
                safe.append(item)
                continue
            safe.append(
                {
                    key: self._text(link[key])
                    for key in ("idReadable", "summary", "direction")
                    if key in link
                }
            )
        return safe

    def _project(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PolicyViolation("project payload must be an object")
        safe = self._project_value(payload) or {}
        if "description" in payload:
            safe["description"] = self._text(payload["description"])
        if "archived" in payload:
            safe["archived"] = bool(payload["archived"])
        return safe

    def _projects(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            raise PolicyViolation("projects payload must be a list")
        return [self._project(item) for item in payload]

    def _article(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PolicyViolation("article payload must be an object")

        safe: dict[str, Any] = {}
        readable_id = payload.get("idReadable") or payload.get("id")
        if readable_id is not None:
            safe["id"] = readable_id
        for key in ("summary", "content"):
            if key in payload:
                safe[key] = self._text(payload[key])
        for key in ("created", "updated", "created_iso8601", "updated_iso8601"):
            if key in payload:
                safe[key] = payload[key]

        project = self._project_value(payload.get("project"))
        if project:
            safe["project"] = project
        return safe

    def _articles(self, payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            raise PolicyViolation("articles payload must be a list")

        safe_articles: list[dict[str, Any]] = []
        text_targets: list[tuple[dict[str, Any], str, str]] = []
        for article in payload:
            if not isinstance(article, dict):
                raise PolicyViolation("article payload must be an object")

            safe: dict[str, Any] = {}
            readable_id = article.get("idReadable") or article.get("id")
            if readable_id is not None:
                safe["id"] = readable_id
            for key in ("summary", "content"):
                value = article.get(key)
                if isinstance(value, str):
                    text_targets.append((safe, key, value))
                elif key in article:
                    safe[key] = self._text(value)
            for key in ("created", "updated", "created_iso8601", "updated_iso8601"):
                if key in article:
                    safe[key] = article[key]
            project = self._project_value(article.get("project"))
            if project:
                safe["project"] = project
            safe_articles.append(safe)

        sanitized_texts = self._texts([value for _, _, value in text_targets])
        for (safe, key, _), value in zip(text_targets, sanitized_texts):
            safe[key] = value
        return safe_articles


class SanitizeRequest(BaseModel):
    tool: str
    payload: Any


class SanitizeResponse(BaseModel):
    payload: Any


@lru_cache(maxsize=1)
def get_policy() -> OutputPolicy:
    return OutputPolicy(PresidioAndSecretsSanitizer())


class RuntimeState:
    """Thread-safe operational state exposed without payload contents."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.ready = False
        self.queued = 0
        self.active = 0
        self.total = 0
        self.failures = 0
        self.rejected = 0
        self.last_duration_seconds = 0.0

    def set_ready(self, ready: bool) -> None:
        with self._lock:
            self.ready = ready

    def queue_started(self) -> None:
        with self._lock:
            self.queued += 1

    def queue_finished(self, *, acquired: bool) -> None:
        with self._lock:
            self.queued -= 1
            if not acquired:
                self.rejected += 1

    def started(self) -> None:
        with self._lock:
            self.active += 1
            self.total += 1

    def finished(self, *, duration_seconds: float, failed: bool) -> None:
        with self._lock:
            self.active -= 1
            self.failures += int(failed)
            self.last_duration_seconds = duration_seconds

    def snapshot(self) -> dict[str, int | float | bool]:
        with self._lock:
            return {
                "workerPid": os.getpid(),
                "ready": self.ready,
                "queued": self.queued,
                "active": self.active,
                "total": self.total,
                "failures": self.failures,
                "rejected": self.rejected,
                "lastDurationSeconds": round(self.last_duration_seconds, 3),
            }


runtime_state = RuntimeState()
sanitizer_slots = threading.BoundedSemaphore(
    max(1, int(os.getenv("SANITIZER_MAX_CONCURRENCY_PER_WORKER", "1")))
)
sanitizer_queue_timeout = max(0.01, float(os.getenv("SANITIZER_QUEUE_TIMEOUT", "5")))


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_policy()
    runtime_state.set_ready(True)
    try:
        yield
    finally:
        runtime_state.set_ready(False)


app = FastAPI(title="YouTrack MCP Sanitizer", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> JSONResponse:
    snapshot = runtime_state.snapshot()
    return JSONResponse(snapshot, status_code=200 if snapshot["ready"] else 503)


@app.get("/metrics")
async def metrics() -> dict[str, int | float | bool]:
    return runtime_state.snapshot()


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    runtime_state.queue_started()
    acquired = sanitizer_slots.acquire(timeout=sanitizer_queue_timeout)
    runtime_state.queue_finished(acquired=acquired)
    if not acquired:
        logger.warning(
            "Rejected sanitizer request for tool '%s': capacity exhausted",
            request.tool,
        )
        raise HTTPException(status_code=503, detail="sanitizer busy")

    runtime_state.started()
    started_at = time.monotonic()
    failed = False
    try:
        payload = get_policy().sanitize(request.tool, request.payload)
    except PolicyViolation as exc:
        failed = True
        logger.warning("Sanitization policy rejected tool '%s'", request.tool)
        raise HTTPException(
            status_code=403, detail="output rejected by policy"
        ) from exc
    except Exception as exc:
        failed = True
        logger.exception("Sanitization failed for tool '%s'", request.tool)
        raise HTTPException(status_code=503, detail="sanitization failed") from exc
    finally:
        duration_seconds = time.monotonic() - started_at
        runtime_state.finished(duration_seconds=duration_seconds, failed=failed)
        sanitizer_slots.release()
        logger.info(
            "Sanitized tool '%s': duration=%.3fs failed=%s",
            request.tool,
            duration_seconds,
            failed,
        )
    return SanitizeResponse(payload=payload)
