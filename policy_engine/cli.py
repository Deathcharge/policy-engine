"""Command-line interface for Samsarix Policy Engine."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Never

from . import __version__
from .artifacts import create_artifact, load_artifact
from .batching import evaluate_batch, load_batch
from .engine import PolicyEngine
from .errors import DocumentLoadError, ValidationError
from .loader import (
    MAX_REQUEST_BYTES,
    _load_json_file,
    load_policy,
    load_request,
    load_request_bytes,
)
from .testing import MAX_TEST_SUITE_BYTES, load_test_suite, run_test_suite

EXIT_ALLOWED = 0
EXIT_TEST_FAILED = 1
EXIT_INVALID = 2
EXIT_DENIED = 3


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        _write_json(
            sys.stderr,
            {"error": {"code": "invalid_command", "message": message}},
            pretty=False,
        )
        raise SystemExit(EXIT_INVALID)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="samsarix-policy",
        description=(
            "Evaluate local JSON action policies with deterministic deny-overrides-allow semantics."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_ArgumentParser)

    validate = subparsers.add_parser("validate", help="validate a policy file")
    validate.add_argument("policy", help="path to a JSON policy")
    validate.add_argument("--pretty", action="store_true", help="indent JSON output")

    check = subparsers.add_parser("check", help="evaluate one action request")
    source = check.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy", "-p", help="path to a JSON policy")
    source.add_argument("--artifact", help="path to a pinned policy artifact")
    check.add_argument("--sha256", help="trusted full artifact digest (required with --artifact)")
    check.add_argument(
        "--application", help="expected application contract (required with --artifact)"
    )
    check.add_argument(
        "--request", "-r", required=True, help="path to a JSON request, or - to read stdin"
    )
    check.add_argument("--explain", action="store_true", help="include per-rule match details")
    check.add_argument("--pretty", action="store_true", help="indent JSON output")

    test = subparsers.add_parser("test", help="run a JSON policy test suite")
    test.add_argument("--policy", "-p", required=True, help="path to a JSON policy")
    test.add_argument("--suite", "-s", required=True, help="path to a JSON policy test suite")
    test.add_argument("--pretty", action="store_true", help="indent JSON output")
    batch = subparsers.add_parser("batch", help="evaluate a bounded JSON request batch")
    batch.add_argument("--policy", "-p", required=True, help="path to a JSON policy")
    batch.add_argument("--batch", "-b", required=True, help="path to a JSON batch document")
    batch.add_argument("--explain", action="store_true", help="include per-rule match details")
    batch.add_argument("--pretty", action="store_true", help="indent JSON output")

    pack = subparsers.add_parser("pack", help="create a deterministic, unsigned policy artifact")
    pack.add_argument("--policy", "-p", required=True)
    pack.add_argument("--revision", required=True)
    pack.add_argument("--application", required=True)
    pack.add_argument("--suite", help="require this JSON suite to pass before packaging")
    pack.add_argument("--output", required=True, help="new artifact file (never overwrites)")
    pack.add_argument("--pretty", action="store_true")

    verify = subparsers.add_parser(
        "verify-artifact", help="verify trusted artifact and application pins"
    )
    verify.add_argument("--artifact", required=True)
    verify.add_argument("--sha256", required=True)
    verify.add_argument("--application", required=True)
    verify.add_argument("--pretty", action="store_true")
    return parser


def _write_json(stream: Any, value: dict[str, Any], *, pretty: bool) -> None:
    json.dump(
        value,
        stream,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=True,
    )
    stream.write("\n")


def _stdin_bytes() -> bytes:
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        payload = buffer.read(MAX_REQUEST_BYTES + 1)
        return payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
    return sys.stdin.read(MAX_REQUEST_BYTES + 1).encode("utf-8")


def _error(exc: Exception, *, pretty: bool) -> int:
    details = list(exc.issues) if isinstance(exc, ValidationError) else []
    payload: dict[str, Any] = {
        "error": {
            "code": "invalid_document",
            "message": str(exc),
        }
    }
    if details:
        payload["error"]["details"] = details
    _write_json(sys.stderr, payload, pretty=pretty)
    return EXIT_INVALID


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        if args.artifact and (not args.sha256 or not args.application):
            parser.error(
                "--artifact requires --sha256 and --application from trusted configuration"
            )
        if args.policy and (args.sha256 or args.application):
            parser.error("--sha256 and --application require --artifact")
    pretty = bool(args.pretty)
    try:
        if args.command == "pack":
            suite = (
                _load_json_file(args.suite, max_bytes=MAX_TEST_SUITE_BYTES) if args.suite else None
            )
            artifact = create_artifact(
                load_policy(args.policy),
                revision=args.revision,
                application=args.application,
                suite=suite,
            )
            payload = artifact.to_bytes()
            try:
                with Path(args.output).open("xb") as handle:
                    handle.write(payload)
            except OSError as exc:
                raise DocumentLoadError(f"could not create artifact: {exc}") from exc
            _write_json(
                sys.stdout,
                {
                    "sha256": artifact.sha256,
                    "revision": artifact.revision,
                    "application": artifact.application,
                },
                pretty=pretty,
            )
            return EXIT_ALLOWED

        if args.command == "verify-artifact":
            artifact = load_artifact(
                args.artifact, expected_sha256=args.sha256, application=args.application
            )
            _write_json(
                sys.stdout,
                {
                    "valid": True,
                    "sha256": artifact.sha256,
                    "revision": artifact.revision,
                    "application": artifact.application,
                },
                pretty=pretty,
            )
            return EXIT_ALLOWED

        if args.command == "validate":
            policy = load_policy(args.policy)
            engine = PolicyEngine(policy)
            _write_json(
                sys.stdout,
                {
                    "valid": True,
                    "policy_id": policy.id,
                    "policy_version": policy.schema_version,
                    "policy_digest": engine.policy_digest,
                    "rule_count": len(policy.rules),
                    "default": policy.default_effect.value,
                },
                pretty=pretty,
            )
            return EXIT_ALLOWED

        policy = (
            load_artifact(
                args.artifact, expected_sha256=args.sha256, application=args.application
            ).policy
            if args.command == "check" and args.artifact
            else load_policy(args.policy)
        )
        engine = PolicyEngine(policy)
        if args.command == "test":
            report = run_test_suite(engine, load_test_suite(args.suite))
            _write_json(sys.stdout, report.to_dict(), pretty=pretty)
            return EXIT_ALLOWED if report.passed else EXIT_TEST_FAILED

        if args.command == "batch":
            result = evaluate_batch(engine, load_batch(args.batch), explain=bool(args.explain))
            _write_json(sys.stdout, result.to_dict(), pretty=pretty)
            return EXIT_ALLOWED

        request = (
            load_request_bytes(_stdin_bytes(), source="stdin")
            if args.request == "-"
            else load_request(args.request)
        )
        decision = engine.evaluate(request, explain=bool(args.explain))
        _write_json(sys.stdout, decision.to_dict(), pretty=pretty)
        return EXIT_ALLOWED if decision.allowed else EXIT_DENIED
    except (DocumentLoadError, ValidationError) as exc:
        return _error(exc, pretty=pretty)


if __name__ == "__main__":
    raise SystemExit(main())
