"""Immutable public data models for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
ConditionValue: TypeAlias = JsonScalar | tuple[JsonScalar, ...]


class Effect(StrEnum):
    """A policy or decision effect."""

    ALLOW = "allow"
    DENY = "deny"


class Operator(StrEnum):
    """Supported condition operators."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    EXISTS = "exists"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"


@dataclass(frozen=True, slots=True)
class Condition:
    """One comparison against a dotted path in request context."""

    path: str
    operator: Operator
    value: ConditionValue


@dataclass(frozen=True, slots=True)
class Rule:
    """A validated policy rule."""

    id: str
    effect: Effect
    principals: tuple[str, ...]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    conditions: tuple[Condition, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class Policy:
    """A validated policy set."""

    id: str
    schema_version: int
    default_effect: Effect
    rules: tuple[Rule, ...]
    description: str = ""


@dataclass(frozen=True, slots=True)
class Request:
    """A principal's requested action on a resource."""

    principal: str
    action: str
    resource: str
    context: dict[str, JsonValue]
    request_id: str | None = None


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """Non-sensitive explanation of how one rule evaluated."""

    rule_id: str
    matched: bool
    mismatches: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "rule_id": self.rule_id,
            "matched": self.matched,
            "mismatches": list(self.mismatches),
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """The deterministic result of evaluating a request."""

    allowed: bool
    effect: Effect
    reason: str
    policy_id: str
    policy_version: int
    policy_digest: str
    request_id: str | None
    matched_rule_ids: tuple[str, ...]
    allow_rule_ids: tuple[str, ...]
    deny_rule_ids: tuple[str, ...]
    evaluations: tuple[RuleEvaluation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-serializable decision contract."""
        result: dict[str, Any] = {
            "allowed": self.allowed,
            "effect": self.effect.value,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "request_id": self.request_id,
            "matched_rule_ids": list(self.matched_rule_ids),
            "allow_rule_ids": list(self.allow_rule_ids),
            "deny_rule_ids": list(self.deny_rule_ids),
        }
        if self.evaluations:
            result["evaluations"] = [evaluation.to_dict() for evaluation in self.evaluations]
        return result
