from __future__ import annotations

import json
from importlib.resources import files


def test_packaged_schema_is_present_and_valid_json() -> None:
    schema = files("policy_engine").joinpath("schemas", "policy.schema.json").read_text()
    assert json.loads(schema)["$schema"] == "https://json-schema.org/draft/2020-12/schema"
