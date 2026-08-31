"""Dependency-free wheel journey, run in isolated mode by verify_distribution."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import policy_engine
from policy_engine import (
    ActionDenied,
    PolicyEngine,
    create_artifact,
    evaluate_batch,
    guarded_call,
    load_artifact,
    load_batch,
    load_policy,
    load_test_suite,
    run_test_suite,
)
from policy_engine.schemas import SCHEMA_NAMES, schema_document


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    assert not Path(policy_engine.__file__).resolve().is_relative_to(root / "policy_engine")
    for name in SCHEMA_NAMES:
        assert files("policy_engine.schemas").joinpath(name).is_file()
        assert schema_document(name)["type"] == "object"
    examples = root / "examples"
    gateway = examples / "agent-tool-gateway"
    engine = PolicyEngine(load_policy(examples / "policy.json"))
    assert run_test_suite(
        PolicyEngine(load_policy(gateway / "policy.json")),
        load_test_suite(gateway / "policy-tests.json"),
    ).passed
    batch = load_batch(examples / "request.batch.json")
    assert [d.allowed for d in evaluate_batch(engine, batch).decisions] == [True, False]
    events = []
    assert (
        guarded_call(engine, batch.requests[0], lambda: "executed", audit_sink=events.append)
        == "executed"
    )
    try:
        guarded_call(
            engine, batch.requests[1], lambda: sys.exit("denial executed"), audit_sink=events.append
        )
    except ActionDenied:
        pass
    else:
        raise AssertionError("denial did not raise")
    assert [event.allowed for event in events] == [True, False]
    artifact = create_artifact(engine.policy, revision="smoke-r1", application="smoke-v1")
    artifact_path = Path.cwd() / "artifact.json"
    artifact_path.write_bytes(artifact.to_bytes())
    assert (
        load_artifact(artifact_path, expected_sha256=artifact.sha256, application="smoke-v1")
        == artifact
    )

    def cli(arguments: list[str], code: int = 0) -> dict:
        result = subprocess.run(
            [sys.executable, "-I", "-m", "policy_engine", *arguments],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == code, (arguments, result.stdout, result.stderr)
        return json.loads(result.stdout if code in (0, 1, 3) else result.stderr)

    cli(["validate", str(examples / "policy.json")])
    cli(
        ["check", "-p", str(examples / "policy.json"), "-r", str(examples / "request.allowed.json")]
    )
    cli(
        ["check", "-p", str(examples / "policy.json"), "-r", str(examples / "request.denied.json")],
        3,
    )
    cli(["check"], 2)
    assert (
        cli(
            [
                "batch",
                "-p",
                str(examples / "policy.json"),
                "-b",
                str(examples / "request.batch.json"),
            ]
        )["count"]
        == 2
    )
    assert (
        cli(["test", "-p", str(gateway / "policy.json"), "-s", str(gateway / "policy-tests.json")])[
            "total"
        ]
        == 7
    )
    packed = Path.cwd() / "tested-artifact.json"
    summary = cli(
        [
            "pack",
            "-p",
            str(gateway / "policy.json"),
            "--revision",
            "r1",
            "--application",
            "gateway-v1",
            "--suite",
            str(gateway / "policy-tests.json"),
            "--output",
            str(packed),
        ]
    )
    assert json.loads(packed.read_bytes())["tests"]["case_count"] == 7
    cli(
        [
            "verify-artifact",
            "--artifact",
            str(packed),
            "--sha256",
            summary["sha256"],
            "--application",
            "gateway-v1",
        ]
    )
    cli(
        [
            "verify-artifact",
            "--artifact",
            str(packed),
            "--sha256",
            "0" * 64,
            "--application",
            "gateway-v1",
        ],
        2,
    )
    assert cli(
        [
            "check",
            "--artifact",
            str(artifact_path),
            "--sha256",
            artifact.sha256,
            "--application",
            "smoke-v1",
            "-r",
            str(examples / "request.allowed.json"),
        ]
    )["allowed"]
    print("Installed check/test/batch/pack/verify-artifact and guarded audit journeys passed.")


if __name__ == "__main__":
    main()
