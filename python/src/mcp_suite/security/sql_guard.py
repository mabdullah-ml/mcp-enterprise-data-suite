"""Strict read-only SQL guardrail blocking DDL/DML, multi-statements, and unbounded scans."""

from __future__ import annotations

import re

FORBIDDEN_KEYWORDS = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "TRUNCATE",
    "CREATE",
    "REPLACE",
    "ATTACH",
    "DETACH",
    "GRANT",
    "REVOKE",
    "PRAGMA",
    "EXEC",
    "EXECUTE",
    "COPY",
    "VACUUM",
    "MERGE",
)

BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT_RE = re.compile(r"--[^\n]*")
LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\b", re.IGNORECASE)
FORBIDDEN_RE = re.compile(
    r"\b(" + "|".join(FORBIDDEN_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


class SQLGuardrailError(ValueError):
    """Raised when a query violates enterprise read-only SQL policy."""


def validate_and_clamp_sql(query: str, max_rows: int = 200) -> str:
    """Validate that SQL is a single read-only SELECT/CTE query and enforce a row LIMIT."""
    if not query or not query.strip():
        raise SQLGuardrailError("SQL query must not be empty.")

    stripped = BLOCK_COMMENT_RE.sub(" ", query)
    stripped = LINE_COMMENT_RE.sub(" ", stripped).strip()
    cleaned = stripped.rstrip(";").strip()

    if ";" in cleaned:
        raise SQLGuardrailError("Multiple SQL statements separated by ';' are forbidden.")

    first_token = cleaned.split(None, 1)[0].upper()
    if first_token not in ("SELECT", "WITH"):
        raise SQLGuardrailError(
            f"Only read-only SELECT or WITH CTE queries are permitted (got '{first_token}')."
        )

    forbidden = FORBIDDEN_RE.search(cleaned)
    if forbidden:
        raise SQLGuardrailError(
            f"Forbidden SQL keyword detected: '{forbidden.group(1).upper()}'."
        )

    limit_match = LIMIT_RE.search(cleaned)
    if limit_match:
        requested = int(limit_match.group(1))
        if requested > max_rows:
            cleaned = LIMIT_RE.sub(f"LIMIT {max_rows}", cleaned, count=1)
        return cleaned

    return f"{cleaned} LIMIT {max_rows}"
