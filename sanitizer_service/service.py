"""Presidio and detect-secrets based sanitization service."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from copy import copy
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException
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
        combined_results = self._analyze_pii(combined)
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


DEFAULT_CUSTOM_FIELDS = {
    "State",
    "Priority",
    "Type",
    "Subsystem",
    "Fix versions",
    "Affected versions",
    "Estimation",
    "Assignee",
}


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
    "search_issues": "issues",
    "get_project_issues": "issues",
    "get_all_issues": "issues",
    "get_issue_comments": "comments",
    "get_issue_links": "links",
    "get_projects": "projects",
    "get_all_projects": "projects",
    "get_project": "project",
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
        configured_fields = os.getenv("SANITIZER_ALLOWED_CUSTOM_FIELDS", "")
        self._custom_fields = (
            {item.strip() for item in configured_fields.split(",") if item.strip()}
            if configured_fields
            else DEFAULT_CUSTOM_FIELDS
        )

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
                or field.get("name") not in self._custom_fields
            ):
                continue
            custom_fields.append(
                {
                    "name": field["name"],
                    "value": self._custom_field_value(
                        field.get("value"), identity=field["name"] == "Assignee"
                    ),
                }
            )
        if custom_fields:
            safe["customFields"] = custom_fields
        return safe

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


class SanitizeRequest(BaseModel):
    tool: str
    payload: Any


class SanitizeResponse(BaseModel):
    payload: Any


@lru_cache(maxsize=1)
def get_policy() -> OutputPolicy:
    return OutputPolicy(PresidioAndSecretsSanitizer())


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_policy()
    yield


app = FastAPI(title="YouTrack MCP Sanitizer", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    try:
        payload = get_policy().sanitize(request.tool, request.payload)
    except PolicyViolation as exc:
        logger.warning("Sanitization policy rejected tool '%s'", request.tool)
        raise HTTPException(
            status_code=403, detail="output rejected by policy"
        ) from exc
    except Exception as exc:
        logger.exception("Sanitization failed for tool '%s'", request.tool)
        raise HTTPException(status_code=503, detail="sanitization failed") from exc
    return SanitizeResponse(payload=payload)
