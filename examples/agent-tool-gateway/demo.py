"""Minimal enforcement-point example; denied operations are never called."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from policy_engine import PolicyEngine, load_policy


def guarded_call(
    engine: PolicyEngine,
    request: Mapping[str, Any],
    operation: Callable[[], Any],
) -> dict[str, Any]:
    """Evaluate first and invoke the operation only when explicitly allowed."""
    decision = engine.evaluate(request)
    if not decision.allowed:
        return {"executed": False, "decision": decision.to_dict(), "result": None}
    return {"executed": True, "decision": decision.to_dict(), "result": operation()}


def _search() -> dict[str, str]:
    return {"status": "simulated", "query": "policy engine comparison"}


def _must_not_execute() -> None:
    raise RuntimeError("denied shell operation was executed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Demonstrate a fail-closed agent tool boundary")
    parser.add_argument("operation", choices=("search", "shell"))
    args = parser.parse_args(argv)

    engine = PolicyEngine(load_policy(Path(__file__).with_name("policy.json")))
    if args.operation == "search":
        request = {
            "principal": "agent:research",
            "action": "tool.invoke",
            "resource": "tool:web.search",
            "context": {"environment": "development"},
        }
        result = guarded_call(engine, request, _search)
    else:
        request = {
            "principal": "agent:research",
            "action": "process.exec",
            "resource": "shell:delete",
            "context": {"environment": "development"},
        }
        result = guarded_call(engine, request, _must_not_execute)

    print(json.dumps(result, sort_keys=True))
    return 0 if result["executed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
