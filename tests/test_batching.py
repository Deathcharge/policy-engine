from __future__ import annotations

import pytest

from policy_engine import (
    BatchRequest,
    BatchValidationError,
    DocumentLoadError,
    PolicyEngine,
    evaluate_batch,
    load_batch,
    parse_batch,
    parse_request,
)
from policy_engine.batching import MAX_BATCH_BYTES, MAX_BATCH_REQUESTS

POLICY = {
    "schema_version": 1,
    "id": "batch-policy",
    "rules": [{"id": "read", "effect": "allow", "actions": ["read"], "resources": ["*"]}],
}


def request(request_id: str, action: str = "read") -> dict[str, str]:
    return {"request_id": request_id, "principal": "user", "action": action, "resource": "doc:1"}


def test_batch_preserves_order_and_correlates_decisions() -> None:
    batch = parse_batch({"schema_version": 1, "requests": [request("a"), request("b", "write")]})
    result = evaluate_batch(PolicyEngine(POLICY), batch)

    assert result.to_dict()["count"] == 2
    assert [decision.request_id for decision in result.decisions] == ["a", "b"]
    assert [decision.allowed for decision in result.decisions] == [True, False]


@pytest.mark.parametrize(
    "document, message",
    [
        ({"schema_version": 1, "requests": []}, "non-empty array"),
        ({"schema_version": 2, "requests": [request("a")]}, "schema_version must be 1"),
        ({"schema_version": True, "requests": [request("a")]}, "schema_version must be 1"),
        (
            {"schema_version": 1, "requests": [{"principal": "u", "action": "a", "resource": "r"}]},
            "request_id is required",
        ),
        ({"schema_version": 1, "requests": [request("a"), request("a")]}, "duplicates 'a'"),
        ({"schema_version": 1, "requests": ["invalid"]}, "must be an object"),
        ({"schema_version": 1, "requests": [request("a")], "extra": True}, "unknown field 'extra'"),
    ],
)
def test_batch_rejects_ambiguous_documents(document, message: str) -> None:
    with pytest.raises(BatchValidationError, match=message):
        parse_batch(document)


def test_batch_request_count_is_bounded() -> None:
    with pytest.raises(BatchValidationError, match=f"exceeds {MAX_BATCH_REQUESTS}"):
        parse_batch(
            {
                "schema_version": 1,
                "requests": [request(str(i)) for i in range(MAX_BATCH_REQUESTS + 1)],
            }
        )


def test_batch_file_size_is_bounded(tmp_path) -> None:
    oversized = tmp_path / "batch.json"
    oversized.write_bytes(b" " * (MAX_BATCH_BYTES + 1))
    with pytest.raises(DocumentLoadError, match="exceeds"):
        load_batch(oversized)


def test_direct_batch_construction_cannot_bypass_invariants() -> None:
    parsed = parse_request(request("same"))
    with pytest.raises(BatchValidationError, match="must be unique"):
        BatchRequest(requests=(parsed, parsed))
    with pytest.raises(BatchValidationError, match="must be non-empty"):
        BatchRequest(requests=())
