from __future__ import annotations

import json

import pytest

from policy_engine import (
    DocumentLoadError,
    PolicyEngine,
    load_test_suite,
    parse_test_suite,
    run_test_suite,
)
from policy_engine import TestSuiteValidationError as SuiteValidationError


def policy() -> dict:
    return {
        "schema_version": 1,
        "id": "tested-policy",
        "rules": [
            {
                "id": "allow-read",
                "effect": "allow",
                "actions": ["read"],
                "resources": ["document:*"],
            },
            {
                "id": "deny-secret",
                "effect": "deny",
                "actions": ["read"],
                "resources": ["document:secret"],
            },
        ],
    }


def suite() -> dict:
    return {
        "schema_version": 1,
        "name": "document access",
        "cases": [
            {
                "name": "public document is readable",
                "request": {
                    "principal": "user:alice",
                    "action": "read",
                    "resource": "document:public",
                },
                "expect": {
                    "allowed": True,
                    "reason": "explicit_allow",
                    "matched_rule_ids": ["allow-read"],
                },
            },
            {
                "name": "explicit deny wins",
                "request": {
                    "principal": "user:alice",
                    "action": "read",
                    "resource": "document:secret",
                },
                "expect": {
                    "allowed": False,
                    "reason": "explicit_deny",
                    "matched_rule_ids": ["allow-read", "deny-secret"],
                },
            },
        ],
    }


def test_parse_and_run_passing_suite() -> None:
    report = run_test_suite(PolicyEngine(policy()), parse_test_suite(suite()))

    assert report.passed is True
    assert report.total == 2
    assert report.passed_count == 2
    assert report.failed_count == 0
    assert report.to_dict()["results"][1]["decision"]["reason"] == "explicit_deny"


def test_report_explains_failed_expectations() -> None:
    document = suite()
    document["cases"][0]["expect"] = {
        "allowed": False,
        "reason": "default_deny",
        "matched_rule_ids": [],
    }

    report = run_test_suite(PolicyEngine(policy()), parse_test_suite(document))

    assert report.passed is False
    assert report.failed_count == 1
    failures = report.results[0].failures
    assert "expected allowed=False, got True" in failures
    assert "expected reason='default_deny', got 'explicit_allow'" in failures
    assert "expected matched_rule_ids=[], got ['allow-read']" in failures


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(schema_version=2), "schema_version"),
        (lambda value: value.update(extra=True), "unknown field"),
        (lambda value: value.update(name=""), "non-empty string"),
        (lambda value: value.update(cases=[]), "non-empty array"),
        (lambda value: value["cases"][0].update(extra=True), "unknown field"),
        (lambda value: value["cases"][0].update(request={}), "request.principal"),
        (lambda value: value["cases"][0].update(expect={}), "allowed"),
        (lambda value: value["cases"][0]["expect"].update(reason=[]), "decision reason"),
        (
            lambda value: value["cases"][0]["expect"].update(
                matched_rule_ids=["allow-read", "allow-read"]
            ),
            "duplicates",
        ),
        (lambda value: value["cases"].append(value["cases"][0].copy()), "duplicates case"),
    ],
)
def test_invalid_suite_is_rejected(mutation, message: str) -> None:
    document = suite()
    mutation(document)

    with pytest.raises(SuiteValidationError, match=message):
        parse_test_suite(document)


def test_load_suite_uses_strict_bounded_json(tmp_path) -> None:
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(suite()), encoding="utf-8")

    assert load_test_suite(path).name == "document access"

    path.write_text('{"schema_version":1,"name":"one","name":"two","cases":[]}', encoding="utf-8")
    with pytest.raises(DocumentLoadError, match="duplicate object key"):
        load_test_suite(path)
