"""PII detection & redaction middleware for MCP tool outputs."""

from __future__ import annotations

import re
from typing import Any

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def redact_text(text: str) -> str:
    redacted = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    redacted = SSN_RE.sub("[REDACTED_SSN]", redacted)
    redacted = PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    return redacted


def redact_payload(payload: Any) -> Any:
    """Recursively mask PII strings in nested dicts/lists."""
    if isinstance(payload, str):
        return redact_text(payload)
    if isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    if isinstance(payload, dict):
        return {k: redact_payload(v) for k, v in payload.items()}
    return payload
