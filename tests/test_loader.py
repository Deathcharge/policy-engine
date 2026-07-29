from __future__ import annotations

import json

import pytest

from policy_engine import DocumentLoadError, load_policy, load_request_bytes
from policy_engine.loader import MAX_JSON_DEPTH, MAX_POLICY_BYTES, decode_json


def test_load_policy_accepts_utf8_bom(tmp_path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps({"schema_version": 1, "id": "bom", "rules": []}).encode("utf-8")
    )
    assert load_policy(path).id == "bom"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'{"key": 1, "key": 2}', "duplicate object key"),
        (b'{"number": NaN}', "non-finite number"),
        (b"[]", "JSON object"),
        (b"{", "strict JSON"),
        (b"\xff", "UTF-8"),
    ],
)
def test_decode_json_rejects_ambiguous_or_invalid_input(payload: bytes, message: str) -> None:
    with pytest.raises(DocumentLoadError, match=message):
        decode_json(payload, source="test", max_bytes=100)


def test_decode_json_enforces_byte_limit() -> None:
    with pytest.raises(DocumentLoadError, match="byte limit"):
        decode_json(b"{} ", source="test", max_bytes=2)


def test_load_policy_rejects_missing_and_oversized_files(tmp_path) -> None:
    with pytest.raises(DocumentLoadError, match="regular file"):
        load_policy(tmp_path / "missing.json")

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    with pytest.raises(DocumentLoadError, match="byte limit"):
        load_policy(oversized)


def test_load_request_bytes_validates_request() -> None:
    request = load_request_bytes(b'{"principal":"u","action":"read","resource":"document:1"}')
    assert request.context == {}


def test_decode_json_turns_excessive_nesting_into_a_safe_error() -> None:
    payload = b'{"value":' + (b"[" * 2_000) + (b"]" * 2_000) + b"}"
    with pytest.raises(DocumentLoadError, match="maximum nesting depth"):
        decode_json(payload, source="deep", max_bytes=10_000)


def test_decode_json_accepts_the_depth_limit_and_ignores_brackets_in_strings() -> None:
    arrays = MAX_JSON_DEPTH - 1  # The root object consumes one nesting level.
    payload = b'{"value":' + (b"[" * arrays) + b'"[ignored]"' + (b"]" * arrays) + b"}"

    assert decode_json(payload, source="boundary", max_bytes=10_000)["value"]
