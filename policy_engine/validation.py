"""Strict parsers for policy and request documents."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from typing import Any, cast

from .errors import PolicyValidationError, RequestValidationError
from .models import Condition, ConditionValue, Effect, Operator, Policy, Request, Rule

MAX_RULES = 512
MAX_PATTERN_ITEMS = 64
MAX_CONDITIONS = 64
MAX_CONTEXT_DEPTH = 16
MAX_CONTEXT_NODES = 10_000
MAX_POLICY_NODES = 250_000
MAX_VALIDATION_ISSUES = 100
MAX_STRING_LENGTH = 16_384
MAX_IDENTIFIER_LENGTH = 128
MAX_PATTERN_LENGTH = 512
MAX_INTEGER_BITS = 4096

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONTEXT_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){0,15}$")
_POLICY_KEYS = {"$schema", "schema_version", "id", "description", "default", "rules"}
_RULE_KEYS = {"id", "description", "effect", "principals", "actions", "resources", "when"}
_REQUEST_KEYS = {"request_id", "principal", "action", "resource", "context"}


class _Issues(list[str]):
    """A diagnostic list that cannot grow without bound."""

    def __init__(self) -> None:
        super().__init__()
        self.dropped = 0

    def append(self, issue: str) -> None:
        if len(self) < MAX_VALIDATION_ISSUES:
            super().append(issue)
        else:
            self.dropped += 1

    def extend(self, issues: Iterable[str]) -> None:
        for issue in issues:
            self.append(issue)

    def finalized(self) -> list[str]:
        result = list(self)
        if self.dropped:
            result.append(f"{self.dropped} additional validation issues omitted")
        return result


def _validate_json_value(
    value: Any, *, label: str, max_nodes: int = MAX_CONTEXT_NODES
) -> list[str]:
    issues = _Issues()
    nodes = 0
    nodes_exceeded = False

    def visit(item: Any, depth: int, path: str) -> None:
        nonlocal nodes, nodes_exceeded
        if nodes_exceeded:
            return
        nodes += 1
        if nodes > max_nodes:
            issues.append(f"{label} exceeds {max_nodes} JSON values")
            nodes_exceeded = True
            return
        if depth > MAX_CONTEXT_DEPTH:
            issues.append(f"{path} exceeds maximum nesting depth {MAX_CONTEXT_DEPTH}")
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, (int, float)):
            if isinstance(item, int) and item.bit_length() > MAX_INTEGER_BITS:
                issues.append(f"{path} exceeds {MAX_INTEGER_BITS} integer bits")
            if isinstance(item, float) and not math.isfinite(item):
                issues.append(f"{path} must be a finite number")
            return
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                issues.append(f"{path} contains an unpaired Unicode surrogate")
            if len(item) > MAX_STRING_LENGTH:
                issues.append(f"{path} exceeds {MAX_STRING_LENGTH} characters")
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                if nodes_exceeded:
                    break
                visit(child, depth + 1, f"{path}[{index}]")
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if nodes_exceeded:
                    break
                if not isinstance(key, str):
                    issues.append(f"{path} contains a non-string object key")
                    continue
                if len(key) > MAX_IDENTIFIER_LENGTH:
                    issues.append(f"{path} contains an overlong object key")
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    issues.append(f"{path} contains a Unicode surrogate in an object key")
                visit(child, depth + 1, f"{path}.{key}")
            return
        issues.append(f"{path} contains unsupported value type {type(item).__name__}")

    visit(value, 0, label)
    return issues


def _unknown_keys(data: Mapping[str, Any], allowed: set[str], label: str) -> list[str]:
    unknown = sorted(str(key) for key in set(data) - allowed)
    result = [f"{label} contains unknown field {key!r}" for key in unknown[:MAX_VALIDATION_ISSUES]]
    if len(unknown) > MAX_VALIDATION_ISSUES:
        result.append(f"{label} contains additional unknown fields")
    return result


def _required_string(
    data: Mapping[str, Any], key: str, label: str, issues: list[str], *, identifier: bool = False
) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{label}.{key} must be a non-empty string")
        return ""
    value = value.strip()
    limit = MAX_IDENTIFIER_LENGTH if identifier else MAX_STRING_LENGTH
    if len(value) > limit:
        issues.append(f"{label}.{key} exceeds {limit} characters")
    if any(ord(character) < 32 for character in value):
        issues.append(f"{label}.{key} contains a control character")
    if identifier and not _IDENTIFIER.fullmatch(value):
        issues.append(f"{label}.{key} must match {_IDENTIFIER.pattern}")
    return value


def _optional_description(data: Mapping[str, Any], label: str, issues: list[str]) -> str:
    value = data.get("description", "")
    if not isinstance(value, str):
        issues.append(f"{label}.description must be a string")
        return ""
    if len(value) > MAX_STRING_LENGTH:
        issues.append(f"{label}.description exceeds {MAX_STRING_LENGTH} characters")
    return value


def _patterns(
    data: Mapping[str, Any],
    key: str,
    label: str,
    issues: list[str],
    *,
    default: list[str] | None = None,
) -> tuple[str, ...]:
    raw = data.get(key, default)
    if not isinstance(raw, list) or not raw:
        issues.append(f"{label}.{key} must be a non-empty array of strings")
        return ()
    if len(raw) > MAX_PATTERN_ITEMS:
        issues.append(f"{label}.{key} exceeds {MAX_PATTERN_ITEMS} patterns")
    patterns: list[str] = []
    for index, pattern in enumerate(raw[:MAX_PATTERN_ITEMS]):
        if not isinstance(pattern, str) or not pattern:
            issues.append(f"{label}.{key}[{index}] must be a non-empty string")
            continue
        if len(pattern) > MAX_PATTERN_LENGTH:
            issues.append(f"{label}.{key}[{index}] exceeds {MAX_PATTERN_LENGTH} characters")
        if any(ord(character) < 32 for character in pattern):
            issues.append(f"{label}.{key}[{index}] contains a control character")
        patterns.append(pattern)
    return tuple(patterns)


def _condition(path: str, raw: Any, label: str, issues: list[str]) -> Condition | None:
    if not _CONTEXT_PATH.fullmatch(path):
        issues.append(f"{label} path {path!r} is not a supported dotted context path")
        return None
    if not isinstance(raw, dict) or len(raw) != 1:
        issues.append(f"{label}.{path} must contain exactly one condition operator")
        return None
    operator_name, value = next(iter(raw.items()))
    try:
        operator = Operator(operator_name)
    except (TypeError, ValueError):
        issues.append(f"{label}.{path} uses unsupported operator {operator_name!r}")
        return None

    scalar = value is None or isinstance(value, (str, int, float, bool))
    if operator is Operator.EXISTS and not isinstance(value, bool):
        issues.append(f"{label}.{path}.exists must be a boolean")
    elif operator in {Operator.IN, Operator.NOT_IN}:
        if not isinstance(value, list) or not value or len(value) > MAX_PATTERN_ITEMS:
            issues.append(
                f"{label}.{path}.{operator.value} must be a non-empty array with at most "
                f"{MAX_PATTERN_ITEMS} values"
            )
        elif not all(item is None or isinstance(item, (str, int, float, bool)) for item in value):
            issues.append(f"{label}.{path}.{operator.value} accepts scalar JSON values only")
    elif operator in {Operator.LT, Operator.LTE, Operator.GT, Operator.GTE}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            issues.append(f"{label}.{path}.{operator.value} must be a number")
    elif operator is Operator.CONTAINS and not scalar:
        issues.append(f"{label}.{path}.contains must be a scalar JSON value")
    elif operator in {Operator.EQUALS, Operator.NOT_EQUALS} and not scalar:
        issues.append(f"{label}.{path}.{operator.value} must be a scalar JSON value")

    issues.extend(_validate_json_value(value, label=f"{label}.{path}.{operator.value}"))
    immutable_value: ConditionValue
    if isinstance(value, list):
        immutable_value = tuple(cast(list[str | int | float | bool | None], value))
    else:
        immutable_value = cast(str | int | float | bool | None, value)
    return Condition(path=path, operator=operator, value=immutable_value)


def parse_policy(data: Mapping[str, Any]) -> Policy:
    """Validate a mapping and return an immutable policy."""
    document = dict(data)
    issues = _Issues()
    issues.extend(_validate_json_value(document, label="policy", max_nodes=MAX_POLICY_NODES))
    issues.extend(_unknown_keys(document, _POLICY_KEYS, "policy"))

    schema_uri = document.get("$schema")
    if "$schema" in document and (
        not isinstance(schema_uri, str)
        or not schema_uri
        or len(schema_uri) > MAX_STRING_LENGTH
        or any(ord(character) < 32 for character in schema_uri)
    ):
        issues.append("policy.$schema must be a non-empty string without control characters")

    schema_version = document.get("schema_version")
    if schema_version != 1 or isinstance(schema_version, bool):
        issues.append("policy.schema_version must be the integer 1")

    policy_id = _required_string(document, "id", "policy", issues, identifier=True)
    description = _optional_description(document, "policy", issues)
    default_raw = document.get("default", Effect.DENY.value)
    try:
        default_effect = Effect(default_raw)
    except (TypeError, ValueError):
        issues.append("policy.default must be 'allow' or 'deny'")
        default_effect = Effect.DENY

    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        issues.append("policy.rules must be an array")
        raw_rules = []
    elif len(raw_rules) > MAX_RULES:
        issues.append(f"policy.rules exceeds {MAX_RULES} rules")

    rules: list[Rule] = []
    rule_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules[:MAX_RULES]):
        label = f"policy.rules[{index}]"
        if not isinstance(raw_rule, dict):
            issues.append(f"{label} must be an object")
            continue
        issues.extend(_unknown_keys(raw_rule, _RULE_KEYS, label))
        rule_id = _required_string(raw_rule, "id", label, issues, identifier=True)
        if rule_id in rule_ids:
            issues.append(f"{label}.id duplicates rule id {rule_id!r}")
        rule_ids.add(rule_id)
        rule_description = _optional_description(raw_rule, label, issues)
        effect_raw = raw_rule.get("effect")
        try:
            effect = Effect(effect_raw) if isinstance(effect_raw, str) else Effect("")
        except ValueError:
            issues.append(f"{label}.effect must be 'allow' or 'deny'")
            effect = Effect.DENY
        principals = _patterns(raw_rule, "principals", label, issues, default=["*"])
        actions = _patterns(raw_rule, "actions", label, issues)
        resources = _patterns(raw_rule, "resources", label, issues)

        raw_when = raw_rule.get("when", {})
        conditions: list[Condition] = []
        if not isinstance(raw_when, dict):
            issues.append(f"{label}.when must be an object")
        else:
            if len(raw_when) > MAX_CONDITIONS:
                issues.append(f"{label}.when exceeds {MAX_CONDITIONS} conditions")
            for path in sorted(raw_when, key=str)[:MAX_CONDITIONS]:
                if not isinstance(path, str):
                    issues.append(f"{label}.when contains a non-string path")
                    continue
                parsed = _condition(path, raw_when[path], f"{label}.when", issues)
                if parsed is not None:
                    conditions.append(parsed)

        rules.append(
            Rule(
                id=rule_id,
                effect=effect,
                principals=principals,
                actions=actions,
                resources=resources,
                conditions=tuple(conditions),
                description=rule_description,
            )
        )

    if issues:
        raise PolicyValidationError(issues.finalized())
    return Policy(
        id=policy_id,
        schema_version=cast(int, schema_version),
        default_effect=default_effect,
        rules=tuple(rules),
        description=description,
    )


def _request_fields(data: Mapping[str, Any]) -> tuple[str, str, str, Any, str | None]:
    """Validate both parsed requests and directly constructed public values."""
    document = dict(data)
    issues = _Issues()
    issues.extend(_validate_json_value(document, label="request"))
    issues.extend(_unknown_keys(document, _REQUEST_KEYS, "request"))
    principal = _required_string(document, "principal", "request", issues)
    action = _required_string(document, "action", "request", issues)
    resource = _required_string(document, "resource", "request", issues)
    for field, value in (("principal", principal), ("action", action), ("resource", resource)):
        if len(value) > MAX_PATTERN_LENGTH:
            issues.append(f"request.{field} exceeds {MAX_PATTERN_LENGTH} characters")

    context = document.get("context", {})
    if not isinstance(context, Mapping):
        issues.append("request.context must be an object")
        context = {}

    request_id_raw = document.get("request_id")
    request_id: str | None
    if request_id_raw is None:
        request_id = None
    elif not isinstance(request_id_raw, str) or not _IDENTIFIER.fullmatch(request_id_raw):
        issues.append(f"request.request_id must match {_IDENTIFIER.pattern}")
        request_id = None
    else:
        request_id = request_id_raw

    if issues:
        raise RequestValidationError(issues.finalized())
    return principal, action, resource, context, request_id


def parse_request(data: Mapping[str, Any]) -> Request:
    """Validate a mapping and return an immutable request."""
    if not isinstance(data, Mapping):
        raise RequestValidationError(["request must be an object"])
    principal, action, resource, context, request_id = _request_fields(data)
    return Request(principal, action, resource, context, request_id)
