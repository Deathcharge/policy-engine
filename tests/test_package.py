from __future__ import annotations

import json
from importlib.metadata import metadata, version
from importlib.resources import files
from pathlib import Path
from urllib.parse import urljoin

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from policy_engine import (
    PolicyEngine,
    __version__,
    load_batch,
    load_policy,
    load_request,
    load_test_suite,
    run_test_suite,
)

ROOT = Path(__file__).resolve().parents[1]


def load_schema(name: str) -> dict:
    payload = files("policy_engine").joinpath("schemas", name).read_text(encoding="utf-8")
    return json.loads(payload)


def validator(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    request_schema = load_schema("request.schema.json")
    request_resource = Resource.from_contents(request_schema)
    registry = Registry().with_resources(
        [
            (request_schema["$id"], request_resource),
            (urljoin(schema["$id"], "request.schema.json"), request_resource),
        ]
    )
    return Draft202012Validator(schema, registry=registry)


def test_packaged_schemas_are_present_and_valid_json() -> None:
    schemas = {
        name: load_schema(name)
        for name in (
            "policy.schema.json",
            "request.schema.json",
            "decision.schema.json",
            "test-suite.schema.json",
            "batch.schema.json",
        )
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

    gateway = ROOT / "examples" / "agent-tool-gateway"
    gateway_policy = gateway / "policy.json"
    gateway_suite = gateway / "policy-tests.json"
    validator("policy.schema.json").validate(json.loads(gateway_policy.read_text(encoding="utf-8")))
    validator("test-suite.schema.json").validate(
        json.loads(gateway_suite.read_text(encoding="utf-8"))
    )
    assert run_test_suite(
        PolicyEngine(load_policy(gateway_policy)), load_test_suite(gateway_suite)
    ).passed

    batch_path = ROOT / "examples" / "request.batch.json"
    validator("batch.schema.json").validate(json.loads(batch_path.read_text(encoding="utf-8")))
    assert len(load_batch(batch_path).requests) == 2


def test_distribution_and_api_versions_match() -> None:
    assert version("samsarix-policy-engine") == __version__

    distribution = metadata("samsarix-policy-engine")
    assert distribution["Name"] == "samsarix-policy-engine"
    assert distribution["License-Expression"] == "BUSL-1.1"
    assert distribution.get_all("License-File") == ["LICENSE"]


def test_benchmark_tools_do_not_become_runtime_dependencies() -> None:
    distribution = metadata("samsarix-policy-engine")
    requirements = distribution.get_all("Requires-Dist", [])
    assert requirements
    assert all("extra ==" in requirement for requirement in requirements)
    benchmark = [requirement for requirement in requirements if requirement.startswith("pyperf")]
    assert len(benchmark) == 1
    assert 'extra == "dev"' in benchmark[0]


def test_license_uses_standard_busl_parameters() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert "Licensor:             Samsarix LLC" in license_text
    assert "Additional Use Grant:" in license_text
    assert "1,000 policy\n                      evaluation requests" in license_text
    assert "Covenants of Licensor" in license_text
    assert "4. Not to modify this License in any other way." in license_text
    assert "California" not in license_text
