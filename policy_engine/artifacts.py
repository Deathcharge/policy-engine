"""Deterministic policy artifacts for pinned, offline deployment (not signatures)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import PolicyEngine, _policy_document
from .errors import ArtifactValidationError
from .loader import _load_json_file
from .models import Policy
from .testing import MAX_TEST_CASES, MAX_TEST_SUITE_BYTES, parse_test_suite, run_test_suite

MAX_ARTIFACT_BYTES = 2_097_152
CANONICALIZATION = "samsarix-json-v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_FIELDS = {"schema_version", "canonicalization", "revision", "application", "policy", "tests"}


def _check_identifier(value: object, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ArtifactValidationError([f"{label} must be a 1-128 character identifier"])


def _check_digest(value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ArtifactValidationError(["sha256 must be 64 lowercase hexadecimal characters"])


def _encode(value: Any, *, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    """Enforce a serialized byte budget and reject non-JSON values."""
    result = bytearray()
    encoder = json.JSONEncoder(
        ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    try:
        for chunk in encoder.iterencode(value):
            result.extend(chunk.encode("ascii"))
            if len(result) > limit:
                raise ArtifactValidationError([f"canonical JSON exceeds {limit} bytes"])
    except (TypeError, ValueError, RecursionError) as exc:
        raise ArtifactValidationError(["value cannot be represented as canonical JSON"]) from exc
    return bytes(result)


@dataclass(frozen=True, slots=True)
class ArtifactTestEvidence:
    """Builder-reported passing suite identity; not independent test attestation."""

    suite_name: str
    suite_sha256: str
    case_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.suite_name, str)
            or not self.suite_name
            or len(self.suite_name) > 128
            or any(ord(c) < 32 for c in self.suite_name)
        ):
            raise ArtifactValidationError(["tests.suite_name must be a non-empty bounded string"])
        _check_digest(self.suite_sha256)
        if type(self.case_count) is not int or not 1 <= self.case_count <= MAX_TEST_CASES:
            raise ArtifactValidationError(["tests.case_count must be an integer from 1 to 1000"])

    def to_dict(self) -> dict[str, Any]:
        """Return evidence without request contexts or test names."""
        return {
            "suite_name": self.suite_name,
            "suite_sha256": self.suite_sha256,
            "case_count": self.case_count,
        }


@dataclass(frozen=True, slots=True)
class PolicyArtifact:
    """A validated immutable policy, application contract, revision, and optional evidence."""

    policy: Policy
    revision: str
    application: str
    tests: ArtifactTestEvidence | None = None

    def __post_init__(self) -> None:
        _check_identifier(self.revision, "revision")
        _check_identifier(self.application, "application")
        if not isinstance(self.policy, (Policy, Mapping)):
            raise ArtifactValidationError(["policy must be a Policy or mapping"])
        if self.tests is not None and not isinstance(self.tests, ArtifactTestEvidence):
            raise ArtifactValidationError(["tests must be ArtifactTestEvidence or None"])
        object.__setattr__(self, "policy", PolicyEngine(self.policy).policy)
        self.to_bytes()  # Every constructible artifact must fit the loader's size limit.

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "canonicalization": CANONICALIZATION,
            "revision": self.revision,
            "application": self.application,
            "policy": _policy_document(self.policy),
            "tests": self.tests.to_dict() if self.tests else None,
        }

    @property
    def sha256(self) -> str:
        """Full digest of all manifest fields, excluding the digest field itself."""
        return hashlib.sha256(_encode(self._payload())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return an independently owned JSON-serializable artifact."""
        return {**self._payload(), "sha256": self.sha256}

    def to_bytes(self) -> bytes:
        """Return canonical ASCII JSON bytes; no newline or platform-specific encoding."""
        return _encode(self.to_dict())


def create_artifact(
    policy: Policy | Mapping[str, Any],
    *,
    revision: str,
    application: str,
    suite: Mapping[str, Any] | None = None,
) -> PolicyArtifact:
    """Build an artifact; when a suite is supplied, require every expectation to pass."""
    engine = PolicyEngine(policy)
    evidence = None
    if suite is not None:
        if not isinstance(suite, Mapping):
            raise ArtifactValidationError(["suite must be a mapping"])
        # Snapshot exactly the supplied JSON; formatting/key order are immaterial to this hash.
        suite_bytes = _encode(dict(suite), limit=MAX_TEST_SUITE_BYTES)
        parsed = parse_test_suite(json.loads(suite_bytes))
        report = run_test_suite(engine, parsed)
        if not report.passed:
            raise ArtifactValidationError([f"policy suite has {report.failed_count} failed cases"])
        evidence = ArtifactTestEvidence(
            parsed.name, hashlib.sha256(suite_bytes).hexdigest(), report.total
        )
    return PolicyArtifact(engine.policy, revision, application, evidence)


def parse_artifact(data: object) -> PolicyArtifact:
    """Check internal integrity only. Use load_artifact with trusted pins for deployment."""
    if not isinstance(data, Mapping) or set(data) != _FIELDS | {"sha256"}:
        raise ArtifactValidationError(
            ["artifact must contain exactly the documented manifest fields"]
        )
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ArtifactValidationError(["artifact.schema_version must be integer 1"])
    if data["canonicalization"] != CANONICALIZATION:
        raise ArtifactValidationError(["unsupported artifact canonicalization"])
    _check_digest(data["sha256"])
    raw_tests = data["tests"]
    tests = None
    if raw_tests is not None:
        if not isinstance(raw_tests, Mapping) or set(raw_tests) != {
            "suite_name",
            "suite_sha256",
            "case_count",
        }:
            raise ArtifactValidationError(
                ["tests must contain exactly suite_name, suite_sha256, case_count"]
            )
        tests = ArtifactTestEvidence(
            raw_tests["suite_name"], raw_tests["suite_sha256"], raw_tests["case_count"]
        )
    if not isinstance(data["policy"], Mapping):
        raise ArtifactValidationError(["artifact.policy must be an object"])
    artifact = PolicyArtifact(
        PolicyEngine(data["policy"]).policy, data["revision"], data["application"], tests
    )
    if not hmac.compare_digest(artifact.sha256, data["sha256"]):
        raise ArtifactValidationError(["artifact integrity check failed"])
    return artifact


def load_artifact(path: str | Path, *, expected_sha256: str, application: str) -> PolicyArtifact:
    """Load for deployment using digest and application pins from trusted configuration."""
    _check_digest(expected_sha256)
    _check_identifier(application, "application")
    artifact = parse_artifact(_load_json_file(path, max_bytes=MAX_ARTIFACT_BYTES))
    if not hmac.compare_digest(artifact.sha256, expected_sha256):
        raise ArtifactValidationError(["artifact does not match trusted sha256 pin"])
    if artifact.application != application:
        raise ArtifactValidationError(["artifact application does not match deployment contract"])
    return artifact
