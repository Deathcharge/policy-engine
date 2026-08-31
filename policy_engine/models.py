"""Immutable public data models for policy evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypeAlias, cast

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
FrozenJsonValue: TypeAlias = (
    JsonScalar | tuple["FrozenJsonValue", ...] | Mapping[str, "FrozenJsonValue"]
)
JsonLike: TypeAlias = JsonValue | FrozenJsonValue
ConditionValue: TypeAlias = JsonScalar | tuple[JsonScalar, ...]


def _freeze_json(value: Any) -> FrozenJsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return cast(JsonScalar, value)


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

    def __post_init__(self) -> None:
        paths = [condition.path for condition in self.conditions]
        if len(paths) != len(set(paths)):
            raise ValueError("rule conditions must use unique paths")


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
    context: Mapping[str, JsonLike]
    request_id: str | None = None

    def __post_init__(self) -> None:
        from .validation import _request_fields

        principal, action, resource, context, request_id = _request_fields(
            {
                "principal": self.principal,
                "action": self.action,
                "resource": self.resource,
                "context": self.context,
                "request_id": self.request_id,
            }
        )
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "context", _freeze_json(context))


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
    evaluations: tuple[RuleEvaluation, ...] | None = None

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
        if self.evaluations is not None:
            result["evaluations"] = [evaluation.to_dict() for evaluation in self.evaluations]
        return result
