"""RBAC policy enforcement, sliding-window rate limiter, and structured audit trail."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

ROLE_SCOPES: dict[str, set[str]] = {
    "analyst": {"sql:read", "kb:search"},
    "engineer": {"sql:read", "kb:search", "ops:ticket_read"},
    "admin": {"sql:read", "kb:search", "ops:ticket_read", "ops:ticket_create", "pii:read"},
}


class AuthorizationError(PermissionError):
    """Raised when a caller role lacks the required MCP tool scope."""


class RateLimitExceededError(RuntimeError):
    """Raised when a caller exceeds its per-minute tool call quota."""


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    caller_id: str
    role: str
    tool_name: str
    allowed: bool
    pii_redacted: bool
    reason: str = ""


@dataclass
class GovernanceController:
    """Enforces RBAC scopes, rate limiting, and immutable audit records."""

    max_calls_per_minute: int = 60
    audit_log: list[AuditEvent] = field(default_factory=list)
    _call_windows: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )

    def has_scope(self, role: str, scope: str) -> bool:
        return scope in ROLE_SCOPES.get(role.lower(), set())

    def authorize(self, caller_id: str, role: str, tool_name: str, required_scope: str) -> bool:
        now = time.monotonic()
        window = self._call_windows[caller_id]
        while window and now - window[0] > 60.0:
            window.popleft()

        if len(window) >= self.max_calls_per_minute:
            self.record_event(
                caller_id=caller_id,
                role=role,
                tool_name=tool_name,
                allowed=False,
                pii_redacted=True,
                reason="Rate limit exceeded",
            )
            raise RateLimitExceededError(
                f"Caller '{caller_id}' exceeded {self.max_calls_per_minute} calls/min."
            )

        if not self.has_scope(role, required_scope):
            self.record_event(
                caller_id=caller_id,
                role=role,
                tool_name=tool_name,
                allowed=False,
                pii_redacted=True,
                reason=f"Missing required scope '{required_scope}'",
            )
            raise AuthorizationError(
                f"Role '{role}' is not authorized for scope '{required_scope}'."
            )

        window.append(now)
        can_view_pii = self.has_scope(role, "pii:read")
        self.record_event(
            caller_id=caller_id,
            role=role,
            tool_name=tool_name,
            allowed=True,
            pii_redacted=not can_view_pii,
            reason="Authorized",
        )
        return not can_view_pii

    def record_event(
        self,
        caller_id: str,
        role: str,
        tool_name: str,
        allowed: bool,
        pii_redacted: bool,
        reason: str = "",
    ) -> None:
        self.audit_log.append(
            AuditEvent(
                timestamp=datetime.now(UTC).isoformat(),
                caller_id=caller_id,
                role=role,
                tool_name=tool_name,
                allowed=allowed,
                pii_redacted=pii_redacted,
                reason=reason,
            )
        )
