from __future__ import annotations

import runpy
from pathlib import Path

from policy_engine import PolicyEngine, load_policy

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "agent-tool-gateway"


def test_agent_tool_gateway_enforces_before_calling_operation() -> None:
    guarded_call = runpy.run_path(str(EXAMPLE / "demo.py"))["guarded_call"]
    engine = PolicyEngine(load_policy(EXAMPLE / "policy.json"))
    called = False

    def operation() -> str:
        nonlocal called
        called = True
        return "executed"

    denied = guarded_call(
        engine,
        {
            "principal": "agent:research",
            "action": "process.exec",
            "resource": "shell:delete",
            "context": {"environment": "development"},
        },
        operation,
    )
    assert denied["executed"] is False
    assert called is False

    allowed = guarded_call(
        engine,
        {
            "principal": "agent:research",
            "action": "tool.invoke",
            "resource": "tool:web.search",
            "context": {"environment": "development"},
        },
        operation,
    )
    assert allowed["executed"] is True
    assert allowed["result"] == "executed"
    assert called is True


def test_pinned_gateway_real_read_and_denied_callback(capsys):
    import json

    example = runpy.run_path(str(ROOT / "examples" / "pinned_gateway.py"))
    example["main"]()
    report = json.loads(capsys.readouterr().out)
    assert report["result"].startswith("A real document read")
    assert not report["denied_operation_executed"]
    assert [event["allowed"] for event in report["audit"]] == [True, False]
