from __future__ import annotations

import pytest

from policy_engine import ActionDenied, AuditDeliveryError, PolicyEngine, Request, guarded_call
from policy_engine.errors import RequestValidationError


def test_guarded_call_enforces_and_audits_in_order():
    engine = PolicyEngine(
        {"schema_version": 1, "id": "secret-policy", "default": "allow", "rules": []}
    )
    request = Request(
        "private-user", "private-action", "private-resource", {"secret": "token"}, "user-1"
    )
    events = []

    def sink(event):
        events.append(event.to_dict())

    def operation():
        assert len(events) == 1
        return 42

    assert guarded_call(engine, request, operation, audit_sink=sink) == 42
    assert events[0]["request_id"] is None
    assert all(
        secret not in str(events) for secret in ("private", "token", "secret-policy", "user-1")
    )
    assert guarded_call(engine, request, lambda: 3, audit_sink=sink, include_request_id=True) == 3
    assert events[-1]["request_id"] == "user-1"
    assert guarded_call(engine, request, lambda: 4) == 4


@pytest.mark.parametrize("allow", [True, False])
def test_audit_failure_prevents_any_operation(allow):
    engine = PolicyEngine(
        {"schema_version": 1, "id": "p", "default": "allow" if allow else "deny", "rules": []}
    )
    calls = []

    def broken_sink(event):
        raise OSError("disk full")

    with pytest.raises(AuditDeliveryError):
        guarded_call(
            engine,
            {"principal": "u", "action": "a", "resource": "r"},
            lambda: calls.append(1),
            audit_sink=broken_sink,
        )
    assert calls == []


def test_denial_and_operation_failure_do_not_retry():
    engine = PolicyEngine({"schema_version": 1, "id": "p", "rules": []})
    calls = []
    events = []
    request = {"principal": "u", "action": "a", "resource": "r"}
    with pytest.raises(ActionDenied) as error:
        guarded_call(engine, request, lambda: calls.append(1), audit_sink=events.append)
    assert error.value.decision.reason == "default_deny"
    assert not events[0].allowed
    assert calls == []
    allow = PolicyEngine({"schema_version": 1, "id": "p", "default": "allow", "rules": []})

    def broken_operation():
        calls.append(1)
        raise RuntimeError("operation failed")

    with pytest.raises(RuntimeError, match="operation failed"):
        guarded_call(allow, request, broken_operation)
    assert calls == [1]


def test_direct_request_constructor_cannot_skip_validation():
    for fields in [
        dict(principal="", action="a", resource="r", context={}),
        dict(principal="u", action="a", resource="r", context={"x": float("nan")}),
        dict(principal="u", action="a", resource="r", context={}, request_id=[]),
    ]:
        with pytest.raises(RequestValidationError):
            Request(**fields)
    cyclic = {}
    cyclic["self"] = cyclic
    with pytest.raises(RequestValidationError):
        Request("u", "a", "r", cyclic)


@pytest.mark.parametrize("context", [{"x": "\ud800"}, {"\udfff": 1}, {"x": 1 << 4096}])
def test_unserializable_request_values_fail_with_structured_error(context):
    with pytest.raises(RequestValidationError):
        Request("u", "a", "r", context)
