from __future__ import annotations

import pytest

from policy_engine import Effect, PolicyEngine, decide, wildcard_match


def policy(*rules: dict, default: str = "deny") -> dict:
    return {
        "schema_version": 1,
        "id": "test-policy",
        "default": default,
        "rules": list(rules),
    }


def rule(
    rule_id: str,
    effect: str,
    *,
    principals: list[str] | None = None,
    actions: list[str] | None = None,
    resources: list[str] | None = None,
    when: dict | None = None,
) -> dict:
    result = {
        "id": rule_id,
        "effect": effect,
        "principals": principals or ["*"],
        "actions": actions or ["read"],
        "resources": resources or ["document:*"],
    }
    if when is not None:
        result["when"] = when
    return result


def request(**overrides: object) -> dict:
    result = {
        "principal": "user:alice",
        "action": "read",
        "resource": "document:public",
        "context": {},
    }
    result.update(overrides)
    return result


def test_explicit_allow_is_deterministic() -> None:
    engine = PolicyEngine(policy(rule("read-documents", "allow")))

    first = engine.evaluate(request())
    second = engine.evaluate(request())

    assert first.allowed is True
    assert first.effect is Effect.ALLOW
    assert first.reason == "explicit_allow"
    assert first.matched_rule_ids == ("read-documents",)
    assert first.request_id is None
    assert second.request_id is None
    assert first.policy_digest == second.policy_digest


def test_default_deny_when_no_rule_matches() -> None:
    decision = decide(policy(rule("write-only", "allow", actions=["write"])), request())

    assert decision.allowed is False
    assert decision.reason == "default_deny"
    assert decision.matched_rule_ids == ()


def test_default_allow_is_supported_but_explicit_deny_wins() -> None:
    open_policy = policy(rule("deny-secret", "deny", resources=["secret:*"]), default="allow")

    ordinary = decide(open_policy, request())
    denied = decide(open_policy, request(resource="secret:token"))

    assert ordinary.allowed is True
    assert ordinary.reason == "default_allow"
    assert denied.allowed is False
    assert denied.reason == "explicit_deny"
    assert denied.deny_rule_ids == ("deny-secret",)


def test_deny_overrides_matching_allow() -> None:
    guarded = policy(
        rule("allow-read", "allow"),
        rule("deny-production", "deny", when={"environment": {"equals": "production"}}),
    )

    decision = decide(guarded, request(context={"environment": "production"}))

    assert decision.allowed is False
    assert decision.allow_rule_ids == ("allow-read",)
    assert decision.deny_rule_ids == ("deny-production",)


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("*", "anything", True),
        ("agent:*", "agent:docs", True),
        ("agent:*", "user:docs", False),
        ("*/secrets/*", "workspace/secrets/key", True),
        ("*.env", ".env", True),
        ("file.?", "file.a", False),
        ("literal[1]", "literal[1]", True),
        ("prefix*suffix", "prefix-middle-suffix", True),
        ("prefix*suffix", "prefix-middle", False),
        ("abc", "abc", True),
        ("abc", "abcd", False),
    ],
)
def test_wildcard_match(pattern: str, value: str, expected: bool) -> None:
    assert wildcard_match(pattern, value) is expected


@pytest.mark.parametrize(
    ("condition", "context", "expected"),
    [
        ({"tier": {"equals": "pro"}}, {"tier": "pro"}, True),
        ({"tier": {"not_equals": "free"}}, {"tier": "pro"}, True),
        ({"tier": {"in": ["pro", "enterprise"]}}, {"tier": "pro"}, True),
        ({"tier": {"not_in": ["free"]}}, {"tier": "pro"}, True),
        ({"roles": {"contains": "admin"}}, {"roles": ["admin", "user"]}, True),
        ({"approval": {"exists": True}}, {"approval": False}, True),
        ({"approval": {"exists": False}}, {}, True),
        ({"risk": {"lt": 5}}, {"risk": 4}, True),
        ({"risk": {"lte": 5}}, {"risk": 5}, True),
        ({"risk": {"gt": 5}}, {"risk": 6}, True),
        ({"risk": {"gte": 5}}, {"risk": 5}, True),
        ({"subject.team": {"equals": "docs"}}, {"subject": {"team": "docs"}}, True),
        ({"missing": {"equals": None}}, {}, False),
        ({"flag": {"equals": 1}}, {"flag": True}, False),
        ({"risk": {"lt": 5}}, {"risk": "4"}, False),
        ({"roles": {"contains": "admin"}}, {"roles": "admin"}, False),
    ],
)
def test_condition_operators(condition: dict, context: dict, expected: bool) -> None:
    conditional = policy(rule("conditional", "allow", when=condition))
    assert decide(conditional, request(context=context)).allowed is expected


def test_explain_reports_fields_not_sensitive_values() -> None:
    engine = PolicyEngine(
        policy(
            rule(
                "conditional",
                "allow",
                principals=["service:*"],
                when={"approval.token": {"exists": True}},
            )
        )
    )

    decision = engine.evaluate(request(context={"approval": {"token": "private"}}), explain=True)
    output = decision.to_dict()

    assert output["evaluations"][0] == {
        "rule_id": "conditional",
        "matched": False,
        "mismatches": ["principal"],
    }
    assert "private" not in str(output)


def test_explain_includes_an_empty_trace_for_a_policy_without_rules() -> None:
    output = decide(policy(), request(), explain=True).to_dict()

    assert output["evaluations"] == []


def test_non_explained_decision_omits_trace() -> None:
    assert "evaluations" not in decide(policy(), request()).to_dict()


def test_explicit_request_id_is_preserved() -> None:
    decision = decide(policy(rule("allow", "allow")), request(request_id="trace-123"))
    assert decision.request_id == "trace-123"


def test_validated_policy_does_not_retain_mutable_condition_values() -> None:
    allowed_tiers = ["pro"]
    document = policy(rule("tier", "allow", when={"tier": {"in": allowed_tiers}}))
    engine = PolicyEngine(document)

    allowed_tiers.clear()

    assert engine.policy.rules[0].conditions[0].value == ("pro",)
    assert engine.evaluate(request(context={"tier": "pro"})).allowed is True
