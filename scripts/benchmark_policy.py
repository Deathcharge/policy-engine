"""Correctness-checked synthetic workloads; optional pyperf runner, not a runtime API."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import policy_engine
from policy_engine import (
    ActionDenied,
    AuditEvent,
    BatchDecision,
    BatchRequest,
    Decision,
    PolicyEngine,
    Request,
    evaluate_batch,
    guarded_call,
    parse_batch,
    parse_request,
)

CORPUS_VERSION = "samsarix-workloads-v1"
GROUPS = ("gateway", "scaling", "batch")


def fingerprint(value: Any) -> str:
    """Hash the exact generated JSON inputs, independent of object key order."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def package_fingerprint() -> str:
    """Identify measured Python sources without relying on a possibly unrelated Git checkout."""
    root = Path(policy_engine.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def gateway_policy(rule_count: int = 8) -> dict[str, Any]:
    """Build two relevant rules plus nonmatching tenant rules for deterministic scale tests."""
    if not 2 <= rule_count <= 512:
        raise ValueError("rule_count must be between 2 and 512")
    rules = [
        {
            "id": "allow-docs",
            "effect": "allow",
            "principals": ["agent:docs"],
            "actions": ["file.read"],
            "resources": ["workspace/public/*"],
            "when": {
                "environment": {"equals": "development"},
                "subject.team": {"equals": "docs"},
                "roles": {"contains": "reader"},
                "risk": {"lte": 3},
            },
        },
        {
            "id": "deny-secrets",
            "effect": "deny",
            "actions": ["file.*"],
            "resources": ["*.env", "*/secrets/*"],
        },
    ]
    rules.extend(
        {
            "id": f"tenant-{index}",
            "effect": "allow",
            "principals": [f"tenant:{index}:*"],
            "actions": ["file.read", "file.write"],
            "resources": [f"tenant/{index}/*"],
            "when": {"approved": {"equals": True}},
        }
        for index in range(rule_count - 2)
    )
    return {"schema_version": 1, "id": "benchmark-gateway", "rules": rules}


def gateway_request(index: int = 0, outcome: str = "allow") -> dict[str, Any]:
    """Generate synthetic attributes only; the deny case matches both relevant rules."""
    if outcome not in ("allow", "deny", "default"):
        raise ValueError("unknown outcome")
    return {
        "request_id": f"request-{index}",
        "principal": "agent:docs",
        "action": "file.write" if outcome == "default" else "file.read",
        "resource": "workspace/public/secrets/key" if outcome == "deny" else "workspace/public/doc",
        "context": {
            "environment": "development",
            "subject": {"team": "docs"},
            "roles": ["reader", "contributor"],
            "risk": 1,
            "approved": False,
        },
    }


def _check_decision(result: object, *, outcome: str, explain: bool = False) -> None:
    """Verify precedence, correlation, and trace shape before any timed sample."""
    if not isinstance(result, Decision):
        raise AssertionError("expected Decision")
    expected_reason = {
        "allow": "explicit_allow",
        "deny": "explicit_deny",
        "default": "default_deny",
    }
    expected_allow = () if outcome == "default" else ("allow-docs",)
    expected_deny = ("deny-secrets",) if outcome == "deny" else ()
    if (
        result.allowed != (outcome == "allow")
        or result.reason != expected_reason[outcome]
        or result.allow_rule_ids != expected_allow
        or result.deny_rule_ids != expected_deny
        or result.request_id != "request-0"
        or (result.evaluations is not None) != explain
        or (explain and len(result.evaluations or ()) != 8)
    ):
        raise AssertionError("gateway decision contract changed")


def _serialize_audit(event: AuditEvent) -> None:
    """Measure minimized JSON conversion without retaining events or pretending to persist them."""
    json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))


def _operation() -> str:
    """A fixed callback isolates guard overhead; real operation cost is intentionally excluded."""
    return "executed"


def _guard_denied(engine: PolicyEngine, request: Request) -> Decision:
    """Include the public denial exception path, never a sensitive real operation."""
    try:
        guarded_call(engine, request, _operation, audit_sink=_serialize_audit)
    except ActionDenied as exc:
        return exc.decision
    raise AssertionError("denied callback was authorized")


def _equal(expected: object, result: object) -> None:
    if result != expected:
        raise AssertionError("benchmark result did not match its fixture")


def _check_batch(result: object, *, count: int, serialized: bool = False) -> None:
    """Assert every ordered result, not just a matching allow count."""
    if serialized:
        if not isinstance(result, str):
            raise AssertionError("expected JSON batch")
        document = json.loads(result)
        decisions = document["decisions"]
    else:
        if not isinstance(result, BatchDecision):
            raise AssertionError("expected BatchDecision")
        decisions = [decision.to_dict() for decision in result.decisions]
    expected = [
        (
            f"request-{index}",
            index % 2 == 0,
            "explicit_allow" if index % 2 == 0 else "explicit_deny",
        )
        for index in range(count)
    ]
    actual = [(item["request_id"], item["allowed"], item["reason"]) for item in decisions]
    _equal(expected, actual)
    for index, item in enumerate(decisions):
        _equal(["allow-docs"], item["allow_rule_ids"])
        _equal([] if index % 2 == 0 else ["deny-secrets"], item["deny_rule_ids"])
        _equal(serialized, "evaluations" in item)
        if serialized:
            _equal(8, len(item["evaluations"]))


@dataclass(frozen=True)
class Workload:
    """A timed public-API call plus untimed correctness and reproducibility information."""

    name: str
    group: str
    operation: Callable[[], object]
    check: Callable[[object], None]
    metadata: dict[str, str | int]

    def verify(self) -> None:
        """Run the exact timed operation once and reject invalid benchmark output."""
        self.check(self.operation())


def workloads() -> tuple[Workload, ...]:
    """Return a fixed, bounded corpus; never import user policies or production data."""
    cases: list[Workload] = []
    policy = gateway_policy()
    engine = PolicyEngine(policy)
    document = gateway_request()
    request = parse_request(document)

    def add(name, group, operation, check, *, policy_doc=policy, inputs=document, units=1):
        cases.append(
            Workload(
                name,
                group,
                operation,
                check,
                {
                    "corpus_version": CORPUS_VERSION,
                    "workload_sha256": fingerprint({"policy": policy_doc, "inputs": inputs}),
                    "rule_count": len(policy_doc["rules"]),
                    "requests_per_call": units,
                },
            )
        )

    add(
        "gateway.construct_engine",
        "gateway",
        partial(PolicyEngine, policy),
        lambda value: _equal(engine.policy_digest, value.policy_digest),
    )
    add(
        "gateway.parse_request",
        "gateway",
        partial(parse_request, document),
        partial(_equal, request),
    )
    for outcome in ("allow", "deny", "default"):
        raw = gateway_request(outcome=outcome)
        add(
            f"gateway.mapping_{outcome}",
            "gateway",
            partial(engine.evaluate, raw),
            partial(_check_decision, outcome=outcome),
            inputs=raw,
        )
    for explain in (False, True):
        add(
            "gateway.parsed_explain" if explain else "gateway.parsed_allow",
            "gateway",
            partial(engine.evaluate, request, explain=explain),
            partial(_check_decision, outcome="allow", explain=explain),
        )
    for audit in (False, True):
        add(
            "gateway.guard_audit_json" if audit else "gateway.guard_no_audit",
            "gateway",
            partial(
                guarded_call,
                engine,
                request,
                _operation,
                audit_sink=_serialize_audit if audit else None,
            ),
            partial(_equal, "executed"),
        )
    denied = gateway_request(outcome="deny")
    add(
        "gateway.guard_denied_audit_json",
        "gateway",
        partial(_guard_denied, engine, parse_request(denied)),
        partial(_check_decision, outcome="deny"),
        inputs=denied,
    )

    for count in (16, 128, 512):
        scaled_policy = gateway_policy(count)
        scaled_engine = PolicyEngine(scaled_policy)
        add(
            f"scaling.parsed_{count}_rules",
            "scaling",
            partial(scaled_engine.evaluate, request),
            partial(_check_decision, outcome="allow"),
            policy_doc=scaled_policy,
        )
    dense_policy = gateway_policy(2)
    dense_policy["rules"][0]["when"] = {f"field_{index}": {"equals": index} for index in range(64)}
    dense_request = gateway_request()
    dense_request["context"] = {f"field_{index}": index for index in range(64)}
    add(
        "scaling.parsed_64_conditions",
        "scaling",
        partial(PolicyEngine(dense_policy).evaluate, parse_request(dense_request)),
        partial(_check_decision, outcome="allow"),
        policy_doc=dense_policy,
        inputs=dense_request,
    )
    pattern_policy = gateway_policy(2)
    pattern_policy["rules"][0]["resources"] = [f"other/{index}/*" for index in range(63)] + [
        "workspace/public/*"
    ]
    add(
        "scaling.parsed_64_patterns",
        "scaling",
        partial(PolicyEngine(pattern_policy).evaluate, request),
        partial(_check_decision, outcome="allow"),
        policy_doc=pattern_policy,
    )

    for count in (1, 100, 1000):
        batch_doc = {
            "schema_version": 1,
            "requests": [
                gateway_request(index, "allow" if index % 2 == 0 else "deny")
                for index in range(count)
            ],
        }
        batch = parse_batch(batch_doc)
        add(
            f"batch.evaluate_{count}",
            "batch",
            partial(evaluate_batch, engine, batch),
            partial(_check_batch, count=count),
            inputs=batch_doc,
            units=count,
        )
        if count == 100:
            add(
                "batch.parse_100",
                "batch",
                partial(parse_batch, batch_doc),
                partial(_equal, batch),
                inputs=batch_doc,
                units=count,
            )
            add(
                "batch.evaluate_explain_json_100",
                "batch",
                partial(_batch_json, engine, batch),
                partial(_check_batch, count=count, serialized=True),
                inputs=batch_doc,
                units=count,
            )
    return tuple(cases)


def _batch_json(engine: PolicyEngine, batch: BatchRequest) -> str:
    """Include evaluation, full explanations, and JSON serialization, but not network transport."""
    return json.dumps(evaluate_batch(engine, batch, explain=True).to_dict(), separators=(",", ":"))


def check_timeout_support(timeout: float | None) -> None:
    """Reject pyperf's unsupported Windows Python 3.11 pipe timeout before spawning workers."""
    if timeout is not None and not hasattr(os, "set_blocking"):
        raise ValueError(
            "--timeout requires os.set_blocking (unavailable on Windows Python 3.11); "
            "use Python 3.12+ or omit this option and apply an external job timeout"
        )


def main() -> None:
    """Run selected workloads with pyperf's isolated workers and calibrated loops."""
    try:
        import pyperf
    except ImportError:
        raise SystemExit(
            'Install the optional tools first: python -m pip install -e ".[dev]"'
        ) from None

    def worker_args(command, args):
        command.extend(("--group", args.group))

    runner = pyperf.Runner(add_cmdline_args=worker_args)
    runner.argparser.add_argument("--group", choices=("all", *GROUPS), default="all")
    args = runner.parse_args()
    try:
        check_timeout_support(args.timeout)
    except ValueError as exc:
        runner.argparser.error(str(exc))
    runner.metadata.update(
        {
            "policy_engine_version": policy_engine.__version__,
            "policy_engine_source_sha256": package_fingerprint(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "timing_boundary": "one call; batch values are per whole batch, not per decision",
        }
    )
    for case in workloads():
        if args.group not in ("all", case.group):
            continue
        case.verify()
        runner.bench_func(case.name, case.operation, metadata=case.metadata)


if __name__ == "__main__":
    main()
