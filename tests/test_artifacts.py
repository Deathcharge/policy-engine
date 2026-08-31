from __future__ import annotations

import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator

from policy_engine import (
    ArtifactTestEvidence,
    ArtifactValidationError,
    DocumentLoadError,
    PolicyArtifact,
    PolicyEngine,
    create_artifact,
    load_artifact,
    parse_artifact,
)
from policy_engine.artifacts import MAX_ARTIFACT_BYTES, _encode
from policy_engine.schemas import SCHEMA_NAMES, schema_document

POLICY = {
    "schema_version": 1,
    "id": "files",
    "rules": [{"id": "read", "effect": "allow", "actions": ["read"], "resources": ["public:*"]}],
}
REQUEST = {"principal": "agent", "action": "read", "resource": "public:guide"}
SUITE = {
    "schema_version": 1,
    "name": "contract-v1",
    "cases": [{"name": "public", "request": REQUEST, "expect": {"allowed": True}}],
}


def make_artifact():
    return create_artifact(POLICY, revision="r1", application="gateway-v1", suite=SUITE)


def test_canonical_golden_digest_across_supported_python_versions():
    artifact = create_artifact(
        {"schema_version": 1, "id": "golden", "rules": []}, revision="r1", application="golden-v1"
    )
    assert artifact.sha256 == "b2ff7aa55ace273e621e56edeb2dc476d1c4eb2a6602f2ada67a7aa34b889837"


def test_invalid_direct_artifact_arguments_are_structured():
    with pytest.raises(ArtifactValidationError, match="policy must"):
        PolicyArtifact(None, "r1", "app")
    with pytest.raises(ArtifactValidationError, match="tests must"):
        PolicyArtifact(PolicyEngine(POLICY).policy, "r1", "app", {})
    with pytest.raises(ArtifactValidationError, match="suite must"):
        create_artifact(POLICY, revision="r1", application="app", suite=[])


def test_artifact_determinism_integrity_and_detachment(tmp_path):
    source = copy.deepcopy(POLICY)
    first = create_artifact(source, revision="r1", application="gateway-v1", suite=SUITE)
    source["rules"].clear()
    second = make_artifact()
    assert first.to_bytes() == second.to_bytes()
    document = first.to_dict()
    digest = document.pop("sha256")
    assert (
        digest
        == hashlib.sha256(
            json.dumps(
                document, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
    )
    path = tmp_path / "policy.artifact.json"
    path.write_bytes(first.to_bytes())
    loaded = load_artifact(path, expected_sha256=digest, application="gateway-v1")
    assert loaded.tests.case_count == 1
    assert PolicyEngine(loaded.policy).evaluate(REQUEST).allowed
    assert parse_artifact(json.loads(first.to_bytes())) == first
    document["policy"]["rules"].clear()
    assert len(first.policy.rules) == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("revision", "r2"),
        ("application", "other"),
        ("schema_version", True),
        ("canonicalization", "jcs"),
        ("policy", []),
        ("tests", {}),
        ("sha256", "INVALID"),
    ],
)
def test_artifact_rejects_tampered_fields(key, value):
    document = make_artifact().to_dict()
    document[key] = value
    with pytest.raises(ArtifactValidationError):
        parse_artifact(document)


@pytest.mark.parametrize("document", [None, [], {}, {"unexpected": 1}])
def test_artifact_rejects_non_documents(document):
    with pytest.raises(ArtifactValidationError):
        parse_artifact(document)


def test_self_consistent_replacement_still_fails_trusted_pin(tmp_path):
    original = make_artifact()
    replacement = create_artifact(POLICY, revision="r2", application="gateway-v1")
    path = tmp_path / "artifact.json"
    path.write_bytes(replacement.to_bytes())
    with pytest.raises(ArtifactValidationError, match="trusted sha256"):
        load_artifact(path, expected_sha256=original.sha256, application="gateway-v1")
    with pytest.raises(ArtifactValidationError, match="application"):
        load_artifact(path, expected_sha256=replacement.sha256, application="other")
    with pytest.raises(ArtifactValidationError, match="64 lowercase"):
        load_artifact(path, expected_sha256="bad", application="gateway-v1")


def test_failed_suite_cannot_produce_artifact():
    suite = copy.deepcopy(SUITE)
    suite["cases"][0]["expect"]["allowed"] = False
    with pytest.raises(ArtifactValidationError, match="failed cases"):
        create_artifact(POLICY, revision="r1", application="gateway-v1", suite=suite)


@pytest.mark.parametrize(
    "name,digest,count",
    [("", "0" * 64, 1), ("test", "x", 1), ("test", "0" * 64, True), ("test", "0" * 64, 0)],
)
def test_evidence_validates_public_constructor(name, digest, count):
    with pytest.raises(ArtifactValidationError):
        ArtifactTestEvidence(name, digest, count)


def test_artifact_limits_and_serialization_errors(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_ARTIFACT_BYTES + 1))
    with pytest.raises(DocumentLoadError, match="exceeds"):
        load_artifact(path, expected_sha256="0" * 64, application="gateway-v1")
    for value, limit in [("long", 2), (float("nan"), 10), (object(), 10)]:
        with pytest.raises(ArtifactValidationError):
            _encode(value, limit=limit)
    with pytest.raises(ArtifactValidationError, match="identifier"):
        create_artifact(POLICY, revision="../r1", application="gateway-v1")


def test_schema_bundles_are_offline_and_validate_artifacts():
    for name in SCHEMA_NAMES:
        schema = schema_document(name)
        Draft202012Validator.check_schema(schema)

        def check_refs(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    assert value["$ref"].startswith("#")
                for child in value.values():
                    check_refs(child)
            elif isinstance(value, list):
                for child in value:
                    check_refs(child)

        check_refs(schema)
    validator = Draft202012Validator(schema_document("artifact.schema.json"))
    validator.validate(make_artifact().to_dict())
    bad = make_artifact().to_dict()
    bad["policy"]["rules"][0]["effect"] = "invalid"
    assert not validator.is_valid(bad)
    with pytest.raises(ValueError, match="unknown"):
        schema_document("../../anything")
