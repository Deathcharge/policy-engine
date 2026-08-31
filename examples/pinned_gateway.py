"""Run an actual temporary workspace read through a pinned artifact and audited guard."""

from __future__ import annotations

import json
import tempfile
from contextlib import suppress
from pathlib import Path

from policy_engine import (
    ActionDenied,
    PolicyEngine,
    create_artifact,
    guarded_call,
    load_artifact,
    load_policy,
)


def main() -> None:
    policy = load_policy(Path(__file__).with_name("policy.json"))
    suite = json.loads(
        Path(__file__).with_name("file-policy-tests.json").read_text(encoding="utf-8")
    )
    artifact = create_artifact(
        policy, revision="files-r1", application="file-gateway-v1", suite=suite
    )
    # This demo is its own trusted builder. Deployments must transport this pin separately.
    trusted_pin = artifact.sha256
    with tempfile.TemporaryDirectory(prefix="samsarix-gateway-") as directory:
        workspace = Path(directory)
        artifact_path = workspace / "policy.artifact.json"
        artifact_path.write_bytes(artifact.to_bytes())
        document = workspace / "guide.txt"
        document.write_text("A real document read, authorized by Samsarix.", encoding="utf-8")
        loaded = load_artifact(
            artifact_path, expected_sha256=trusted_pin, application="file-gateway-v1"
        )
        engine = PolicyEngine(loaded.policy)
        events = []
        # Map a trusted logical resource to a known file; do not use request strings as paths.
        allowed = {
            "principal": "agent:demo",
            "action": "file.read",
            "resource": "workspace/public/guide.txt",
        }
        result = guarded_call(
            engine, allowed, lambda: document.read_text(encoding="utf-8"), audit_sink=events.append
        )
        denied = {**allowed, "resource": "secrets/.env"}
        called = False

        def forbidden_operation():
            nonlocal called
            called = True
            raise AssertionError("secret operation should not execute")

        with suppress(ActionDenied):
            guarded_call(engine, denied, forbidden_operation, audit_sink=events.append)
        assert not called
        print(
            json.dumps(
                {
                    "revision": loaded.revision,
                    "artifact_sha256": loaded.sha256,
                    "result": result,
                    "denied_operation_executed": called,
                    "audit": [event.to_dict() for event in events],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
