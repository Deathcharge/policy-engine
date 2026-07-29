from __future__ import annotations

import json
from importlib.metadata import metadata, version
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from policy_engine import PolicyEngine, __version__, load_policy, load_request

ROOT = Path(__file__).resolve().parents[1]


def load_schema(name: str) -> dict:
    payload = files("policy_engine").joinpath("schemas", name).read_text(encoding="utf-8")
    return json.loads(payload)


def test_packaged_schemas_are_present_and_valid_json() -> None:
    schemas = {
        name: load_schema(name)
        for name in ("policy.schema.json", "request.schema.json", "decision.schema.json")
    }

    assert all(
        schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        for schema in schemas.values()
    )
    assert len({schema["$id"] for schema in schemas.values()}) == len(schemas)
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)


def test_examples_conform_to_public_schemas() -> None:
    policy_path = ROOT / "examples" / "policy.json"
    policy_document = json.loads(policy_path.read_text(encoding="utf-8"))
    Draft202012Validator(load_schema("policy.schema.json")).validate(policy_document)

    engine = PolicyEngine(load_policy(policy_path))
    request_validator = Draft202012Validator(load_schema("request.schema.json"))
    decision_validator = Draft202012Validator(load_schema("decision.schema.json"))
    for filename in ("request.allowed.json", "request.denied.json"):
        request_path = ROOT / "examples" / filename
        request_document = json.loads(request_path.read_text(encoding="utf-8"))
        request_validator.validate(request_document)
        decision_validator.validate(engine.evaluate(load_request(request_path)).to_dict())


def test_distribution_and_api_versions_match() -> None:
    assert version("samsarix-policy-engine") == __version__

    distribution = metadata("samsarix-policy-engine")
    assert distribution["Name"] == "samsarix-policy-engine"
    assert distribution["License-Expression"] == "BUSL-1.1"
    assert distribution.get_all("License-File") == ["LICENSE"]


def test_license_uses_standard_busl_parameters() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert "Licensor:             Samsarix LLC" in license_text
    assert "Additional Use Grant:" in license_text
    assert "1,000 policy\n                      evaluation requests" in license_text
    assert "Covenants of Licensor" in license_text
    assert "4. Not to modify this License in any other way." in license_text
    assert "California" not in license_text
