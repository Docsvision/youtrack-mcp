"""Daily YouTrack-backed dictionary for pseudonymizing customer companies."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from youtrack_mcp.api.client import YouTrackClient
from youtrack_mcp.api.pagination import get_all_pages

logger = logging.getLogger(__name__)

COMPANY_PREFIX = "COMPANY"
INDIVIDUAL_TERM_EXCLUSIONS = {
    "ао",
    "зао",
    "компания",
    "нко",
    "оао",
    "ооо",
    "пао",
    "предприятие",
    "фгуп",
    "company",
    "corporation",
    "group",
    "inc",
    "llc",
    "ltd",
}

ACRONYM_EXCLUSIONS = {
    "ао",
    "зао",
    "нко",
    "оао",
    "ооо",
    "пао",
    "фгуп",
    "corporation",
    "inc",
    "llc",
    "ltd",
}


class CompanyDictionaryError(RuntimeError):
    """Raised when the company dictionary cannot protect output safely."""


class YouTrackCompanyLoader:
    """Read enum values for one project custom field through read-only REST calls."""

    def __init__(
        self,
        client: YouTrackClient,
        project_id: str = "SUP",
        field_name: str = "Клиент",
    ) -> None:
        self._client = client
        self._project_id = project_id
        self._field_name = field_name

    def __call__(self) -> list[str]:
        project_fields = get_all_pages(
            self._client,
            f"admin/projects/{self._project_id}/customFields",
            fields="id,field(name),bundle(id),$type",
        )
        field = next(
            (
                item
                for item in project_fields
                if isinstance(item, dict)
                and isinstance(item.get("field"), dict)
                and item["field"].get("name") == self._field_name
            ),
            None,
        )
        if field is None:
            raise CompanyDictionaryError(
                f"custom field '{self._field_name}' was not found in project "
                f"'{self._project_id}'"
            )

        bundle = field.get("bundle")
        bundle_id = bundle.get("id") if isinstance(bundle, dict) else None
        if not bundle_id:
            raise CompanyDictionaryError(
                f"custom field '{self._field_name}' has no readable enum bundle"
            )

        values = get_all_pages(
            self._client,
            f"admin/customFieldSettings/bundles/enum/{bundle_id}/values",
            fields="id,name",
        )
        names = [
            str(item["name"]).strip()
            for item in values
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        ]
        if not names:
            raise CompanyDictionaryError("company dictionary is empty")
        return names


@dataclass(frozen=True)
class CompanyReplacement:
    expression: re.Pattern[str]
    alias: str


class CompanyDictionaryRedactor:
    """Refresh company names periodically and replace their aliases recursively."""

    def __init__(
        self,
        loader: Callable[[], Iterable[str]],
        *,
        key: str | bytes | None = None,
        refresh_seconds: float = 86400,
        required: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if refresh_seconds <= 0:
            raise ValueError("refresh_seconds must be positive")
        self._loader = loader
        self._key = self._prepare_key(key)
        self._refresh_seconds = refresh_seconds
        self._required = required
        self._clock = clock
        self._lock = threading.Lock()
        self._replacements: tuple[CompanyReplacement, ...] = ()
        self._refresh_after = 0.0

    @staticmethod
    def _prepare_key(key: str | bytes | None) -> bytes:
        if isinstance(key, bytes) and key:
            return key
        if isinstance(key, str) and key:
            return key.encode("utf-8")
        logger.warning(
            "No company pseudonym key is configured; aliases change after restart"
        )
        return secrets.token_bytes(32)

    @staticmethod
    def _normalize(value: str) -> str:
        return " ".join(value.replace("\u00a0", " ").split()).strip()

    @staticmethod
    def _tokens(value: str) -> list[str]:
        return re.findall(r"[^\W_]+", value, flags=re.UNICODE)

    def _alias(self, company: str) -> str:
        normalized = self._normalize(company).casefold()
        digest = hmac.new(
            self._key,
            normalized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:10]
        return f"{COMPANY_PREFIX}-{digest}"

    @staticmethod
    def _pattern(value: str) -> str:
        parts = re.split(r"([\s\u00a0]+)", value)
        return "".join(
            r"[\s\u00a0]+" if part and part[0].isspace() else re.escape(part)
            for part in parts
            if part
        )

    def _candidate_terms(self, company: str) -> set[str]:
        normalized = self._normalize(company)
        tokens = self._tokens(normalized)
        individual_tokens = [
            token
            for token in tokens
            if token.casefold() not in INDIVIDUAL_TERM_EXCLUSIONS
        ]
        terms = {normalized}
        terms.update(
            token
            for token in individual_tokens
            if len(token) >= 4 or (len(token) >= 2 and token.isupper())
        )
        has_explicit_acronym = any(
            2 <= len(token) <= 5
            and token.isupper()
            and token.casefold() not in ACRONYM_EXCLUSIONS
            for token in tokens
        )
        if not has_explicit_acronym:
            acronym_tokens = [
                token for token in tokens if token.casefold() not in ACRONYM_EXCLUSIONS
            ]
            acronym = "".join(token[0] for token in acronym_tokens if token).upper()
            if 2 <= len(acronym) <= 10:
                terms.add(acronym)
        return {term for term in terms if term}

    def _build_replacements(
        self, companies: Iterable[str]
    ) -> tuple[CompanyReplacement, ...]:
        owners: dict[str, set[str]] = defaultdict(set)
        canonical: dict[str, str] = {}
        for raw_company in companies:
            company = self._normalize(str(raw_company))
            if not company:
                continue
            company_key = company.casefold()
            canonical.setdefault(company_key, company)
            for term in self._candidate_terms(company):
                owners[self._normalize(term).casefold()].add(company_key)

        replacements = []
        for term_key, company_keys in owners.items():
            if len(company_keys) != 1:
                continue
            company_key = next(iter(company_keys))
            expression = re.compile(
                rf"(?<!\w){self._pattern(term_key)}(?!\w)",
                flags=re.IGNORECASE | re.UNICODE,
            )
            replacements.append(
                CompanyReplacement(expression, self._alias(canonical[company_key]))
            )
        replacements.sort(
            key=lambda item: len(item.expression.pattern),
            reverse=True,
        )
        return tuple(replacements)

    def _ensure_fresh(self) -> None:
        now = self._clock()
        if self._replacements and now < self._refresh_after:
            return

        with self._lock:
            now = self._clock()
            if self._replacements and now < self._refresh_after:
                return
            try:
                companies = list(self._loader())
                replacements = self._build_replacements(companies)
                if not replacements:
                    raise CompanyDictionaryError(
                        "company dictionary produced no safe replacement terms"
                    )
            except Exception as exc:
                if self._replacements:
                    logger.warning(
                        "Company dictionary refresh failed; retaining stale cache"
                    )
                    self._refresh_after = now + min(self._refresh_seconds, 300)
                    return
                if self._required:
                    raise CompanyDictionaryError(
                        "initial company dictionary refresh failed"
                    ) from exc
                logger.warning("Company dictionary unavailable; redaction is disabled")
                self._refresh_after = now + min(self._refresh_seconds, 300)
                return

            self._replacements = replacements
            self._refresh_after = now + self._refresh_seconds
            logger.info(
                "Company dictionary refreshed: %d companies, %d unambiguous terms",
                len(companies),
                len(replacements),
            )

    def _redact_text(self, value: str) -> str:
        for replacement in self._replacements:
            value = replacement.expression.sub(replacement.alias, value)
        return value

    def _redact_value(self, payload: Any) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload)
        if isinstance(payload, list):
            return [self._redact_value(item) for item in payload]
        if isinstance(payload, dict):
            return {key: self._redact_value(value) for key, value in payload.items()}
        return payload

    def redact(self, payload: Any) -> Any:
        self._ensure_fresh()
        return self._redact_value(payload)
