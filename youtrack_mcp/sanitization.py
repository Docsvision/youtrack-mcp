"""Central output-sanitization boundary for MCP tool results.

PII and secret detection are delegated to a dedicated local sanitizer service
instead of being reimplemented in the MCP process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol

import requests

from youtrack_mcp.config import Config

logger = logging.getLogger(__name__)


class SanitizationError(RuntimeError):
    """Raised when an MCP result cannot be sanitized safely."""


class OutputSanitizer(Protocol):
    """Backend contract used by the central MCP output boundary."""

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        """Return a sanitized payload for one MCP tool invocation."""


class OutputPreprocessor(Protocol):
    """Local defense-in-depth preprocessing before the sidecar call."""

    def redact(self, payload: Any) -> Any:
        """Return a payload with locally managed dictionary terms redacted."""


class PassthroughSanitizer:
    """Compatibility backend used when no sanitizer service is configured."""

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        return payload


class UnavailableSanitizer:
    """Fail-closed backend used when protected mode lacks a sidecar URL."""

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        raise SanitizationError(
            "sanitizer is required but YOUTRACK_SANITIZER_URL is not configured"
        )


@dataclass(frozen=True)
class HttpOutputSanitizer:
    """Client for a local, independently deployable sanitizer service."""

    url: str
    timeout_seconds: float
    connect_timeout_seconds: float = 2.0

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        try:
            response = requests.post(
                self.url,
                json={"tool": tool_name, "payload": payload},
                timeout=(self.connect_timeout_seconds, self.timeout_seconds),
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise SanitizationError("sanitizer service request failed") from exc

        if not isinstance(body, dict) or "payload" not in body:
            raise SanitizationError("sanitizer service returned an invalid response")

        return body["payload"]


class CachingOutputSanitizer:
    """Bounded safe-result cache with duplicate in-flight request coalescing."""

    def __init__(
        self,
        sanitizer: OutputSanitizer,
        *,
        ttl_seconds: float = 300.0,
        max_entries: int = 256,
    ) -> None:
        self._sanitizer = sanitizer
        self._ttl_seconds = max(0.0, ttl_seconds)
        self._max_entries = max(0, max_entries)
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._inflight: dict[str, Future[Any]] = {}

    @staticmethod
    def _key(tool_name: str, payload: Any) -> str | None:
        try:
            serialized = json.dumps(
                [tool_name, payload],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def sanitize(self, tool_name: str, payload: Any) -> Any:
        key = self._key(tool_name, payload)
        if key is None or self._ttl_seconds == 0 or self._max_entries == 0:
            return self._sanitizer.sanitize(tool_name, payload)

        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                expires_at, result = cached
                if expires_at > now:
                    self._cache.move_to_end(key)
                    return deepcopy(result)
                del self._cache[key]

            pending = self._inflight.get(key)
            if pending is None:
                pending = Future()
                self._inflight[key] = pending
                owner = True
            else:
                owner = False

        if not owner:
            return deepcopy(pending.result())

        try:
            result = self._sanitizer.sanitize(tool_name, payload)
            safe_result = deepcopy(result)
        except BaseException as exc:
            with self._lock:
                self._inflight.pop(key, None)
                pending.set_exception(exc)
            raise

        with self._lock:
            self._cache[key] = (time.monotonic() + self._ttl_seconds, safe_result)
            self._cache.move_to_end(key)
            while len(self._cache) > self._max_entries:
                self._cache.popitem(last=False)
            self._inflight.pop(key, None)
            pending.set_result(safe_result)
        return deepcopy(safe_result)


class OutputSanitizationBoundary:
    """Mandatory boundary applied to every registered MCP tool result."""

    def __init__(
        self,
        sanitizer: OutputSanitizer,
        fail_closed: bool = True,
        preprocessors: tuple[OutputPreprocessor, ...] = (),
    ):
        self._sanitizer = sanitizer
        self._fail_closed = fail_closed
        self._preprocessors = preprocessors

    @staticmethod
    def _decode_resource_text(payload: Any) -> Any:
        """Expose JSON nested in MCP resource ``contents[].text`` to the backend."""
        if not isinstance(payload, dict) or not isinstance(
            payload.get("contents"), list
        ):
            return payload

        decoded = dict(payload)
        decoded["contents"] = []
        for content in payload["contents"]:
            item = dict(content) if isinstance(content, dict) else content
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                try:
                    item["text"] = json.loads(item["text"])
                except json.JSONDecodeError:
                    pass
            decoded["contents"].append(item)
        return decoded

    @staticmethod
    def _encode_resource_text(payload: Any) -> Any:
        """Restore the MCP resource text field after structural sanitization."""
        if not isinstance(payload, dict) or not isinstance(
            payload.get("contents"), list
        ):
            return payload

        for content in payload["contents"]:
            if isinstance(content, dict) and not isinstance(content.get("text"), str):
                content["text"] = json.dumps(content.get("text"), ensure_ascii=False)
        return payload

    def sanitize(self, tool_name: str, result: Any) -> Any:
        was_json_string = False
        payload = result

        if isinstance(result, str):
            try:
                payload = json.loads(result)
                was_json_string = True
            except json.JSONDecodeError:
                payload = result

        payload = self._decode_resource_text(payload)

        try:
            if tool_name != "get_issue_image":
                for preprocessor in self._preprocessors:
                    payload = preprocessor.redact(payload)
            sanitized = self._sanitizer.sanitize(tool_name, payload)
        except Exception as exc:
            logger.error("Output sanitization failed for tool '%s'", tool_name)
            if self._fail_closed:
                raise SanitizationError(
                    f"output blocked because sanitization failed for tool '{tool_name}'"
                ) from exc
            logger.warning(
                "Fail-open mode returned an unsanitized result for tool '%s'",
                tool_name,
            )
            return result

        sanitized = self._encode_resource_text(sanitized)

        if was_json_string:
            return json.dumps(sanitized, indent=2, ensure_ascii=False)
        return sanitized


@lru_cache(maxsize=1)
def get_output_sanitization_boundary() -> OutputSanitizationBoundary:
    """Build the process-wide boundary from environment-backed configuration."""

    if Config.SANITIZER_URL:
        backend: OutputSanitizer = CachingOutputSanitizer(
            HttpOutputSanitizer(
                url=Config.SANITIZER_URL,
                timeout_seconds=Config.SANITIZER_TIMEOUT,
                connect_timeout_seconds=Config.SANITIZER_CONNECT_TIMEOUT,
            ),
            ttl_seconds=Config.SANITIZER_CACHE_TTL,
            max_entries=Config.SANITIZER_CACHE_MAX_ENTRIES,
        )
    elif Config.SANITIZER_REQUIRED:
        backend = UnavailableSanitizer()
    else:
        backend = PassthroughSanitizer()

    preprocessors: tuple[OutputPreprocessor, ...] = ()
    if Config.COMPANY_SANITIZATION_ENABLED and (
        Config.SANITIZER_URL or Config.SANITIZER_REQUIRED
    ):
        from youtrack_mcp.api.client import YouTrackClient
        from youtrack_mcp.company_sanitization import (
            CompanyDictionaryRedactor,
            YouTrackCompanyLoader,
        )

        explicit_key = Config.COMPANY_PSEUDONYM_KEY
        if explicit_key:
            company_key: str | bytes | None = explicit_key
        else:
            token = Config.get_api_token()
            company_key = hashlib.sha256(
                b"youtrack-company-pseudonym-v1\0" + token.encode("utf-8")
            ).digest()
        client = YouTrackClient()
        loader = YouTrackCompanyLoader(
            client,
            project_id=Config.COMPANY_PROJECT,
            field_name=Config.COMPANY_FIELD,
        )
        preprocessors = (
            CompanyDictionaryRedactor(
                loader,
                key=company_key,
                refresh_seconds=Config.COMPANY_REFRESH_SECONDS,
                required=Config.COMPANY_SANITIZATION_REQUIRED,
            ),
        )

    return OutputSanitizationBoundary(
        sanitizer=backend,
        fail_closed=Config.SANITIZER_FAIL_CLOSED,
        preprocessors=preprocessors,
    )
