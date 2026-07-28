from __future__ import annotations

import copy

import pytest

from policy_engine import PolicyValidationError, RequestValidationError, parse_policy, parse_request


def valid_policy() -> dict:
    return {
        "schema_version": 1,
        "id": "valid",
        "rules": [
            {
                "id": "allow",
                "effect": "allow",
                "actions": ["read"],
                "resources": ["document:*"],
            }
        ],
    }


def test_policy_defaults_to_deny_and_all_principals() -> None:
    parsed = parse_policy(valid_policy())
    assert parsed.default_effect.value == "deny"
    assert parsed.rules[0].principals == ("*",)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(schema_version=2), "schema_version"),
        (lambda value: value.update({"$schema": 1}), r"policy\.\$schema"),
        (lambda value: value.update(unknown=True), "unknown field"),
        (lambda value: value.update(id="bad id"), "must match"),
        (lambda value: value.update(default="maybe"), "default"),
        (lambda value: value.update(rules="bad"), "rules must be an array"),
        (lambda value: value["rules"].append(copy.deepcopy(value["rules"][0])), "duplicates"),
        (lambda value: value["rules"][0].update(effect="maybe"), "effect"),
        (lambda value: value["rules"][0].update(actions=[]), "non-empty array"),
        (lambda value: value["rules"][0].update(when={"bad path": {"equals": 1}}), "dotted"),
        (lambda value: value["rules"][0].update(when={"risk": {"regex": ".*"}}), "unsupported"),
        (lambda value: value["rules"][0].update(when={"risk": {"exists": "yes"}}), "boolean"),
        (lambda value: value["rules"][0].update(when={"risk": {"lt": True}}), "number"),
    ],
)
def test_invalid_policy_is_rejected(mutation, message: str) -> None:
    document = valid_policy()
    mutation(document)
    with pytest.raises(PolicyValidationError, match=message):
        parse_policy(document)


def test_empty_rules_is_a_valid_default_deny_policy() -> None:
    document = valid_policy()
    document["rules"] = []
    assert parse_policy(document).rules == ()


@pytest.mark.parametrize(
    "document",
    [
        {"action": "read", "resource": "x"},
        {"principal": "u", "resource": "x"},
        {"principal": "u", "action": "read"},
        {"principal": "u", "action": "read", "resource": "x", "context": []},
        {"principal": "u", "action": "read", "resource": "x", "extra": True},
        {"request_id": "bad id", "principal": "u", "action": "read", "resource": "x"},
    ],
)
def test_invalid_request_is_rejected(document: dict) -> None:
    with pytest.raises(RequestValidationError):
        parse_request(document)


def test_context_depth_and_non_finite_numbers_are_bounded() -> None:
    nested: dict = {}
    current = nested
    for _ in range(18):
        current["child"] = {}
        current = current["child"]
    with pytest.raises(RequestValidationError, match="nesting depth"):
        parse_request({"principal": "u", "action": "a", "resource": "r", "context": nested})

    with pytest.raises(RequestValidationError, match="finite number"):
        parse_request(
            {"principal": "u", "action": "a", "resource": "r", "context": {"n": float("inf")}}
        )


def test_request_control_characters_are_rejected() -> None:
    with pytest.raises(RequestValidationError, match="control character"):
        parse_request({"principal": "user\nadmin", "action": "read", "resource": "x"})

    with pytest.raises(RequestValidationError, match="exceeds 512 characters"):
        parse_request({"principal": "u" * 513, "action": "read", "resource": "x"})


def test_conditions_and_diagnostics_are_bounded() -> None:
    document = valid_policy()
    document["rules"][0]["when"] = {f"field{index}": {"unknown": index} for index in range(200)}
    with pytest.raises(PolicyValidationError) as raised:
        parse_policy(document)
    assert len(raised.value.issues) <= 101
    assert any("exceeds 64 conditions" in issue for issue in raised.value.issues)
