"""Bounded batch evaluation for latency-sensitive authorization workloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import PolicyEngine
from .errors import BatchValidationError, RequestValidationError
from .loader import _load_json_file
from .models import Decision, Request
from .validation import parse_request

MAX_BATCH_REQUESTS = 1_000
MAX_BATCH_BYTES = 2_097_152
MAX_BATCH_ISSUES = 100


@dataclass(frozen=True, slots=True)
class BatchRequest:
    """A validated, correlation-safe collection of authorization requests."""

    requests: tuple[Request, ...]
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class BatchDecision:
    """Deterministic decisions returned in the same order as their requests."""

    policy_id: str
    policy_version: int
    policy_digest: str
    decisions: tuple[Decision, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "count": len(self.decisions),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


def parse_batch(data: Mapping[str, Any]) -> BatchRequest:
    """Validate a versioned batch document with unique correlation identifiers."""
    issues: list[str] = []
    unknown = sorted(set(data) - {"schema_version", "requests"})
    issues.extend(f"batch contains unknown field {field!r}" for field in unknown[:MAX_BATCH_ISSUES])
    schema_version = data.get("schema_version")
    if schema_version != 1 or isinstance(schema_version, bool):
        issues.append("batch.schema_version must be 1")

    raw_requests = data.get("requests")
    if not isinstance(raw_requests, list) or not raw_requests:
        issues.append("batch.requests must be a non-empty array")
        raw_requests = []
    elif len(raw_requests) > MAX_BATCH_REQUESTS:
        issues.append(f"batch.requests exceeds {MAX_BATCH_REQUESTS} requests")

    requests: list[Request] = []
    seen_ids: set[str] = set()
    for index, raw_request in enumerate(raw_requests[:MAX_BATCH_REQUESTS]):
        label = f"batch.requests[{index}]"
        if not isinstance(raw_request, Mapping):
            issues.append(f"{label} must be an object")
            continue
        try:
            request = parse_request(raw_request)
        except RequestValidationError as exc:
            issues.extend(f"{label}: {issue}" for issue in exc.issues)
            continue
        if request.request_id is None:
            issues.append(f"{label}.request_id is required for batch correlation")
        elif request.request_id in seen_ids:
            issues.append(f"{label}.request_id duplicates {request.request_id!r}")
        else:
            seen_ids.add(request.request_id)
        requests.append(request)
        if len(issues) >= MAX_BATCH_ISSUES:
            break

    if issues:
        raise BatchValidationError(issues[:MAX_BATCH_ISSUES])
    return BatchRequest(requests=tuple(requests))


def load_batch(path: str | Path) -> BatchRequest:
    """Load one strict, size-bounded batch JSON document."""
    return parse_batch(_load_json_file(path, max_bytes=MAX_BATCH_BYTES))


def evaluate_batch(
    engine: PolicyEngine, batch: BatchRequest, *, explain: bool = False
) -> BatchDecision:
    """Evaluate a validated batch while preserving input order."""
    decisions = tuple(engine.evaluate(request, explain=explain) for request in batch.requests)
    return BatchDecision(
        policy_id=engine.policy.id,
        policy_version=engine.policy.schema_version,
        policy_digest=engine.policy_digest,
        decisions=decisions,
    )
