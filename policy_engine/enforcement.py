"""Synchronous action-boundary enforcement and opt-in, data-minimized decision audit."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from .engine import PolicyEngine
from .errors import PolicyEngineError
from .models import Decision, Request

T = TypeVar("T")


class ActionDenied(PolicyEngineError, PermissionError):
    """The operation was not invoked because its policy decision denied access."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.reason)


class AuditDeliveryError(PolicyEngineError):
    """The caller's audit sink failed; no operation was invoked."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Decision-only record: no principal, action, resource, context, or rule names."""

    allowed: bool
    reason: str
    policy_digest: str
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the versioned event contract; not an operation-success receipt."""
        return {
            "schema_version": 1,
            "event": "policy_decision",
            "allowed": self.allowed,
            "reason": self.reason,
            "policy_digest": self.policy_digest,
            "request_id": self.request_id,
        }


def guarded_call(
    engine: PolicyEngine,
    request: Request | Mapping[str, Any],
    operation: Callable[[], T],
    *,
    audit_sink: Callable[[AuditEvent], None] | None = None,
    include_request_id: bool = False,
) -> T:
    """Authorize, optionally audit, then invoke once; deny or audit failure prevents invocation.

    The synchronous sink provides backpressure. Its timeout, persistence, and retention are owned
    by the caller. Operation exceptions propagate without retries. Request IDs are omitted unless
    explicitly opted in, since they can contain identifying information.
    """
    decision = engine.evaluate(request)
    if audit_sink is not None:
        event = AuditEvent(
            decision.allowed,
            decision.reason,
            decision.policy_digest,
            decision.request_id if include_request_id else None,
        )
        try:
            audit_sink(event)
        except Exception as exc:
            raise AuditDeliveryError("audit sink failed; operation not invoked") from exc
    if not decision.allowed:
        raise ActionDenied(decision)
    return operation()
