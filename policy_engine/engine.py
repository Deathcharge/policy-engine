"""Deterministic policy evaluation with deny-overrides-allow semantics."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, TypeGuard

from .models import (
    Condition,
    Decision,
    Effect,
    JsonLike,
    Operator,
    Policy,
    Request,
    Rule,
    RuleEvaluation,
)
from .validation import parse_policy, parse_request

_MISSING = object()


def wildcard_match(pattern: str, value: str) -> bool:
    """Match a bounded string using only ``*`` as a wildcard."""
    if "*" not in pattern:
        return pattern == value

    parts = pattern.split("*")
    position = 0
    middle_start = 0
    middle_end = len(parts)

    if parts[0]:
        if not value.startswith(parts[0]):
            return False
        position = len(parts[0])
        middle_start = 1

    search_end = len(value)
    if parts[-1]:
        if not value.endswith(parts[-1]):
            return False
        search_end = len(value) - len(parts[-1])
        middle_end -= 1
        if search_end < position:
            return False

    for part in parts[middle_start:middle_end]:
        if not part:
            continue
        found = value.find(part, position, search_end)
        if found < 0:
            return False
        position = found + len(part)
    return position <= search_end


def _matches_any(patterns: tuple[str, ...], value: str) -> bool:
    return any(wildcard_match(pattern, value) for pattern in patterns)


def _context_value(context: Mapping[str, JsonLike], path: str) -> JsonLike | object:
    current: JsonLike | object = context
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def _is_number(value: Any) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _json_equal(left: Any, right: Any) -> bool:
    if _is_number(left) and _is_number(right):
        return bool(left == right)
    return type(left) is type(right) and bool(left == right)


def _condition_matches(condition: Condition, context: Mapping[str, JsonLike]) -> bool:
    actual = _context_value(context, condition.path)
    expected = condition.value
    operator = condition.operator

    if operator is Operator.EXISTS:
        return (actual is not _MISSING) is expected
    if actual is _MISSING:
        return False
    if operator is Operator.EQUALS:
        return _json_equal(actual, expected)
    if operator is Operator.NOT_EQUALS:
        return not _json_equal(actual, expected)
    if operator is Operator.IN:
        return isinstance(expected, tuple) and any(_json_equal(actual, item) for item in expected)
    if operator is Operator.NOT_IN:
        return isinstance(expected, tuple) and not any(
            _json_equal(actual, item) for item in expected
        )
    if operator is Operator.CONTAINS:
        return isinstance(actual, (list, tuple)) and any(
            _json_equal(item, expected) for item in actual
        )
    if not (_is_number(actual) and _is_number(expected)):
        return False
    if operator is Operator.LT:
        return bool(actual < expected)
    if operator is Operator.LTE:
        return bool(actual <= expected)
    if operator is Operator.GT:
        return bool(actual > expected)
    if operator is Operator.GTE:
        return bool(actual >= expected)
    return False


def _evaluate_rule(rule: Rule, request: Request) -> RuleEvaluation:
    mismatches: list[str] = []
    if not _matches_any(rule.principals, request.principal):
        mismatches.append("principal")
    if not _matches_any(rule.actions, request.action):
        mismatches.append("action")
    if not _matches_any(rule.resources, request.resource):
        mismatches.append("resource")
    for condition in rule.conditions:
        if not _condition_matches(condition, request.context):
            mismatches.append(f"context.{condition.path}")
    return RuleEvaluation(rule_id=rule.id, matched=not mismatches, mismatches=tuple(mismatches))


def _policy_document(policy: Policy) -> dict[str, Any]:
    return {
        "schema_version": policy.schema_version,
        "id": policy.id,
        "description": policy.description,
        "default": policy.default_effect.value,
        "rules": [
            {
                "id": rule.id,
                "description": rule.description,
                "effect": rule.effect.value,
                "principals": list(rule.principals),
                "actions": list(rule.actions),
                "resources": list(rule.resources),
                "when": {
                    condition.path: {
                        condition.operator.value: (
                            list(condition.value)
                            if isinstance(condition.value, tuple)
                            else condition.value
                        )
                    }
                    for condition in rule.conditions
                },
            }
            for rule in policy.rules
        ],
    }


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()[:32]


class PolicyEngine:
    """Evaluate immutable policy sets against structured action requests."""

    def __init__(self, policy: Policy | Mapping[str, Any]):
        self.policy = (
            parse_policy(_policy_document(policy))
            if isinstance(policy, Policy)
            else parse_policy(policy)
        )
        self.policy_digest = _digest(_policy_document(self.policy))

    def evaluate(self, request: Request | Mapping[str, Any], *, explain: bool = False) -> Decision:
        """Return an allow/deny decision. Deny rules always override allow rules."""
        parsed_request = request if isinstance(request, Request) else parse_request(request)
        evaluations = tuple(_evaluate_rule(rule, parsed_request) for rule in self.policy.rules)
        matched_rules = tuple(
            rule
            for rule, evaluation in zip(self.policy.rules, evaluations, strict=True)
            if evaluation.matched
        )
        allow_ids = tuple(rule.id for rule in matched_rules if rule.effect is Effect.ALLOW)
        deny_ids = tuple(rule.id for rule in matched_rules if rule.effect is Effect.DENY)

        if deny_ids:
            effect = Effect.DENY
            reason = "explicit_deny"
        elif allow_ids:
            effect = Effect.ALLOW
            reason = "explicit_allow"
        else:
            effect = self.policy.default_effect
            reason = f"default_{effect.value}"

        return Decision(
            allowed=effect is Effect.ALLOW,
            effect=effect,
            reason=reason,
            policy_id=self.policy.id,
            policy_version=self.policy.schema_version,
            policy_digest=self.policy_digest,
            request_id=parsed_request.request_id,
            matched_rule_ids=tuple(rule.id for rule in matched_rules),
            allow_rule_ids=allow_ids,
            deny_rule_ids=deny_ids,
            evaluations=evaluations if explain else None,
        )


def decide(
    policy: Policy | Mapping[str, Any],
    request: Request | Mapping[str, Any],
    *,
    explain: bool = False,
) -> Decision:
    """Evaluate one request without retaining an engine instance."""
    return PolicyEngine(policy).evaluate(request, explain=explain)
