"""Packaged JSON Schema access without network resolution or optional dependencies."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

SCHEMA_NAMES = (
    "policy.schema.json",
    "request.schema.json",
    "decision.schema.json",
    "test-suite.schema.json",
    "batch.schema.json",
    "artifact.schema.json",
)


def schema_document(name: str) -> dict[str, Any]:
    """Return a self-contained Draft 2020-12 document with all references bundled.

    Pass the result to your preferred validator. No URL is fetched. Unknown schema names or
    external references fail rather than falling back to network retrieval.
    """
    if name not in SCHEMA_NAMES:
        raise ValueError("unknown packaged schema name")
    documents = {
        key: json.loads(files(__package__).joinpath(key).read_text(encoding="utf-8"))
        for key in SCHEMA_NAMES
    }

    def rewrite(value: Any, current: str) -> Any:
        prefix = "#" if current == name else f"#/$defs/{current}"
        if isinstance(value, list):
            return [rewrite(item, current) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "$id":
                continue
            if key == "$ref":
                if item.startswith("#"):
                    result[key] = prefix + item[1:]
                else:
                    target = item.rsplit("/", 1)[-1]
                    if target not in documents or item not in (target, documents[target]["$id"]):
                        raise ValueError("unrecognized external schema reference")
                    result[key] = "#" if target == name else f"#/$defs/{target}"
            else:
                result[key] = rewrite(item, current)
        return result

    root: dict[str, Any] = rewrite(documents[name], name)
    definitions = root.setdefault("$defs", {})
    definitions.update({key: rewrite(doc, key) for key, doc in documents.items() if key != name})
    return root
