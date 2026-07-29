"""Bounded, ambiguity-resistant JSON document loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import DocumentLoadError
from .models import Policy, Request
from .validation import parse_policy, parse_request

MAX_POLICY_BYTES = 1_048_576
MAX_REQUEST_BYTES = 262_144
MAX_JSON_DEPTH = 64


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _enforce_max_json_depth(text: str, *, source: str) -> None:
    """Reject deeply nested containers without relying on interpreter recursion limits."""
    depth = 0
    in_string = False
    escaped = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise DocumentLoadError(
                    f"{source} is not valid strict JSON: maximum nesting depth "
                    f"{MAX_JSON_DEPTH} exceeded"
                )
        elif character in "]}":
            depth -= 1


def decode_json(payload: bytes, *, source: str, max_bytes: int) -> dict[str, Any]:
    """Decode one bounded JSON object while rejecting duplicate keys and NaN values."""
    if len(payload) > max_bytes:
        raise DocumentLoadError(f"{source} exceeds the {max_bytes}-byte limit")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DocumentLoadError(f"{source} is not valid UTF-8") from exc
    _enforce_max_json_depth(text, source=source)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite number {constant!r}")
            ),
        )
    except (json.JSONDecodeError, _DuplicateKeyError, RecursionError, ValueError) as exc:
        raise DocumentLoadError(f"{source} is not valid strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DocumentLoadError(f"{source} must contain a JSON object")
    return value


def _read_file(path: str | Path, *, max_bytes: int) -> bytes:
    document_path = Path(path)
    try:
        if not document_path.is_file():
            raise DocumentLoadError(f"{document_path} is not a regular file")
        with document_path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
    except DocumentLoadError:
        raise
    except OSError as exc:
        raise DocumentLoadError(f"could not read {document_path}: {exc}") from exc
    if len(payload) > max_bytes:
        raise DocumentLoadError(f"{document_path} exceeds the {max_bytes}-byte limit")
    return payload


def load_policy(path: str | Path) -> Policy:
    """Load and validate a JSON policy file."""
    payload = _read_file(path, max_bytes=MAX_POLICY_BYTES)
    return parse_policy(decode_json(payload, source=str(path), max_bytes=MAX_POLICY_BYTES))


def load_request(path: str | Path) -> Request:
    """Load and validate a JSON request file."""
    payload = _read_file(path, max_bytes=MAX_REQUEST_BYTES)
    return parse_request(decode_json(payload, source=str(path), max_bytes=MAX_REQUEST_BYTES))


def load_request_bytes(payload: bytes, *, source: str = "request input") -> Request:
    """Load and validate request JSON from an in-memory byte string."""
    return parse_request(decode_json(payload, source=source, max_bytes=MAX_REQUEST_BYTES))
