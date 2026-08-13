"""Bounded, executable policy expectations for authoring and CI."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import PolicyEngine
from .errors import RequestValidationError, TestSuiteValidationError
from .loader import _load_json_file
from .models import Decision, Request
from .validation import MAX_IDENTIFIER_LENGTH, MAX_RULES, parse_request

MAX_TEST_CASES = 1_000
MAX_TEST_SUITE_BYTES = 1_048_576
MAX_TEST_NAME_LENGTH = 128
MAX_TEST_ISSUES = 100

_SUITE_KEYS = {"$schema", "schema_version", "name", "cases"}
_CASE_KEYS = {"name", "request", "expect"}
_EXPECTATION_KEYS = {"allowed", "reason", "matched_rule_ids"}
_DECISION_REASONS = {"explicit_allow", "explicit_deny", "default_allow", "default_deny"}


@dataclass(frozen=True, slots=True)
class PolicyTestExpectation:
    """Expected observable fields for one policy decision."""

    allowed: bool
    reason: str | None = None
    matched_rule_ids: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class PolicyTestCase:
    """One named request and its expected decision."""

    name: str
    request: Request
    expect: PolicyTestExpectation


@dataclass(frozen=True, slots=True)
class PolicyTestSuite:
    """A validated collection of policy expectations."""

    name: str
    schema_version: int
    cases: tuple[PolicyTestCase, ...]


@dataclass(frozen=True, slots=True)
class PolicyTestResult:
    """The result of checking one expectation."""

    name: str
    passed: bool
    failures: tuple[str, ...]
    decision: Decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "failures": list(self.failures),
            "decision": self.decision.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class PolicyTestReport:
    """Stable aggregate output for local and CI policy tests."""

    suite_name: str
    policy_id: str
    policy_digest: str
    results: tuple[PolicyTestResult, ...]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed_count(self) -> int:
        return sum(result.passed for result in self.results)

    @property
    def failed_count(self) -> int:
        return self.total - self.passed_count

    @property
    def passed(self) -> bool:
        return self.failed_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite_name,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "passed": self.passed,
            "total": self.total,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "results": [result.to_dict() for result in self.results],
        }


class _Issues(list[str]):
    def append(self, issue: str) -> None:
        if len(self) < MAX_TEST_ISSUES:
            super().append(issue)

    def extend(self, issues: Any) -> None:
        for issue in issues:
            self.append(str(issue))


def _unknown_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> list[str]:
    unknown = sorted(str(key) for key in set(value) - allowed)
    return [f"{label} contains unknown field {key!r}" for key in unknown]


def _name(value: Any, *, label: str, issues: _Issues) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEST_NAME_LENGTH
        or any(ord(character) < 32 for character in value)
    ):
        issues.append(
            f"{label} must be a non-empty string of at most {MAX_TEST_NAME_LENGTH} characters "
            "without control characters"
        )
        return ""
    return value


def _expectation(value: Any, *, label: str, issues: _Issues) -> PolicyTestExpectation | None:
    if not isinstance(value, dict):
        issues.append(f"{label} must be an object")
        return None
    issues.extend(_unknown_keys(value, _EXPECTATION_KEYS, label))

    allowed = value.get("allowed")
    if not isinstance(allowed, bool):
        issues.append(f"{label}.allowed must be a boolean")

    reason = value.get("reason")
    valid_reason = reason is None or (isinstance(reason, str) and reason in _DECISION_REASONS)
    if not valid_reason:
        issues.append(f"{label}.reason must be a supported decision reason")

    raw_rule_ids = value.get("matched_rule_ids")
    matched_rule_ids: tuple[str, ...] | None = None
    if raw_rule_ids is not None:
        if not isinstance(raw_rule_ids, list):
            issues.append(f"{label}.matched_rule_ids must be an array")
        elif len(raw_rule_ids) > MAX_RULES:
            issues.append(f"{label}.matched_rule_ids exceeds {MAX_RULES} entries")
        elif not all(
            isinstance(item, str)
            and item
            and len(item) <= MAX_IDENTIFIER_LENGTH
            and not any(ord(character) < 32 for character in item)
            for item in raw_rule_ids
        ):
            issues.append(
                f"{label}.matched_rule_ids must contain non-empty strings of at most "
                f"{MAX_IDENTIFIER_LENGTH} characters without control characters"
            )
        elif len(raw_rule_ids) != len(set(raw_rule_ids)):
            issues.append(f"{label}.matched_rule_ids must not contain duplicates")
        else:
            matched_rule_ids = tuple(raw_rule_ids)

    if not isinstance(allowed, bool) or not valid_reason:
        return None
    return PolicyTestExpectation(
        allowed=allowed,
        reason=reason,
        matched_rule_ids=matched_rule_ids,
    )


def parse_test_suite(data: Mapping[str, Any]) -> PolicyTestSuite:
    """Validate a test-suite mapping and return immutable expectations."""
    document = dict(data)
    issues = _Issues()
    issues.extend(_unknown_keys(document, _SUITE_KEYS, "test suite"))

    schema_uri = document.get("$schema")
    if "$schema" in document and (
        not isinstance(schema_uri, str)
        or not schema_uri
        or len(schema_uri) > 16_384
        or any(ord(character) < 32 for character in schema_uri)
    ):
        issues.append("test suite.$schema must be a non-empty string without control characters")

    schema_version = document.get("schema_version")
    if schema_version != 1 or isinstance(schema_version, bool):
        issues.append("test suite.schema_version must be the integer 1")
    suite_name = _name(document.get("name"), label="test suite.name", issues=issues)

    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        issues.append("test suite.cases must be a non-empty array")
        raw_cases = []
    elif len(raw_cases) > MAX_TEST_CASES:
        issues.append(f"test suite.cases exceeds {MAX_TEST_CASES} cases")

    cases: list[PolicyTestCase] = []
    names: set[str] = set()
    for index, value in enumerate(raw_cases[:MAX_TEST_CASES]):
        label = f"test suite.cases[{index}]"
        if not isinstance(value, dict):
            issues.append(f"{label} must be an object")
            continue
        issues.extend(_unknown_keys(value, _CASE_KEYS, label))
        case_name = _name(value.get("name"), label=f"{label}.name", issues=issues)
        if case_name in names:
            issues.append(f"{label}.name duplicates case name {case_name!r}")
        names.add(case_name)

        raw_request = value.get("request")
        request: Request | None = None
        if not isinstance(raw_request, dict):
            issues.append(f"{label}.request must be an object")
        else:
            try:
                request = parse_request(raw_request)
            except RequestValidationError as exc:
                issues.extend(f"{label}.request: {issue}" for issue in exc.issues)

        expectation = _expectation(value.get("expect"), label=f"{label}.expect", issues=issues)
        if case_name and request is not None and expectation is not None:
            cases.append(PolicyTestCase(name=case_name, request=request, expect=expectation))

    if issues:
        raise TestSuiteValidationError(issues)
    return PolicyTestSuite(name=suite_name, schema_version=1, cases=tuple(cases))


def load_test_suite(path: str | Path) -> PolicyTestSuite:
    """Load one bounded strict-JSON policy test suite."""
    return parse_test_suite(_load_json_file(path, max_bytes=MAX_TEST_SUITE_BYTES))


def run_test_suite(engine: PolicyEngine, suite: PolicyTestSuite) -> PolicyTestReport:
    """Evaluate all suite cases and return a machine-readable report."""
    results: list[PolicyTestResult] = []
    for case in suite.cases:
        decision = engine.evaluate(case.request)
        failures: list[str] = []
        if decision.allowed is not case.expect.allowed:
            failures.append(f"expected allowed={case.expect.allowed}, got {decision.allowed}")
        if case.expect.reason is not None and decision.reason != case.expect.reason:
            failures.append(f"expected reason={case.expect.reason!r}, got {decision.reason!r}")
        if (
            case.expect.matched_rule_ids is not None
            and decision.matched_rule_ids != case.expect.matched_rule_ids
        ):
            failures.append(
                "expected matched_rule_ids="
                f"{list(case.expect.matched_rule_ids)!r}, got {list(decision.matched_rule_ids)!r}"
            )
        results.append(
            PolicyTestResult(
                name=case.name,
                passed=not failures,
                failures=tuple(failures),
                decision=decision,
            )
        )
    return PolicyTestReport(
        suite_name=suite.name,
        policy_id=engine.policy.id,
        policy_digest=engine.policy_digest,
        results=tuple(results),
    )
