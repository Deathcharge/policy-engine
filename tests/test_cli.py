from __future__ import annotations

import io
import json
import sys

import pytest

from policy_engine.cli import EXIT_ALLOWED, EXIT_DENIED, EXIT_INVALID, EXIT_TEST_FAILED, main


def write_documents(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "cli-policy",
                "rules": [
                    {
                        "id": "allow-read",
                        "effect": "allow",
                        "actions": ["read"],
                        "resources": ["public:*"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    allowed = tmp_path / "allowed.json"
    allowed.write_text(
        json.dumps({"principal": "u", "action": "read", "resource": "public:1"}),
        encoding="utf-8",
    )
    denied = tmp_path / "denied.json"
    denied.write_text(
        json.dumps({"principal": "u", "action": "write", "resource": "public:1"}),
        encoding="utf-8",
    )
    return policy, allowed, denied


def test_validate_command(tmp_path, capsys) -> None:
    policy, _, _ = write_documents(tmp_path)
    assert main(["validate", str(policy)]) == EXIT_ALLOWED
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["rule_count"] == 1


def test_check_exit_codes_and_output(tmp_path, capsys) -> None:
    policy, allowed, denied = write_documents(tmp_path)

    assert main(["check", "-p", str(policy), "-r", str(allowed)]) == EXIT_ALLOWED
    assert json.loads(capsys.readouterr().out)["allowed"] is True

    assert main(["check", "-p", str(policy), "-r", str(denied), "--explain"]) == EXIT_DENIED
    output = json.loads(capsys.readouterr().out)
    assert output["allowed"] is False
    assert output["evaluations"][0]["mismatches"] == ["action"]


def test_check_reads_request_from_stdin(tmp_path, capsys, monkeypatch) -> None:
    policy, _, _ = write_documents(tmp_path)
    payload = b'{"principal":"u","action":"read","resource":"public:stdin"}'
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8"))

    assert main(["check", "-p", str(policy), "-r", "-"]) == EXIT_ALLOWED
    assert json.loads(capsys.readouterr().out)["allowed"] is True


def test_invalid_document_uses_stderr_and_exit_two(tmp_path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")

    assert main(["validate", str(invalid), "--pretty"]) == EXIT_INVALID
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "invalid_document"


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == 0
    assert "samsarix-policy 0.1.0" in capsys.readouterr().out


def test_invalid_command_is_structured_json(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["check"])
    assert raised.value.code == EXIT_INVALID
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "invalid_command"


def test_policy_test_command_reports_passes_and_assertion_failures(tmp_path, capsys) -> None:
    policy, _, _ = write_documents(tmp_path)
    suite = tmp_path / "suite.json"
    suite.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "CLI suite",
                "cases": [
                    {
                        "name": "public read",
                        "request": {
                            "principal": "u",
                            "action": "read",
                            "resource": "public:1",
                        },
                        "expect": {"allowed": True, "reason": "explicit_allow"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert main(["test", "-p", str(policy), "-s", str(suite), "--pretty"]) == EXIT_ALLOWED
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is True
    assert report["total"] == 1

    document = json.loads(suite.read_text(encoding="utf-8"))
    document["cases"][0]["expect"]["allowed"] = False
    suite.write_text(json.dumps(document), encoding="utf-8")

    assert main(["test", "-p", str(policy), "-s", str(suite)]) == EXIT_TEST_FAILED
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False
    assert report["failed_count"] == 1


def test_artifact_cli_journey_and_no_overwrite(tmp_path, capsys):
    policy, allowed, denied = write_documents(tmp_path)
    artifact = tmp_path / "artifact.json"
    pack_args = [
        "pack",
        "-p",
        str(policy),
        "--revision",
        "r1",
        "--application",
        "cli-v1",
        "--output",
        str(artifact),
    ]
    assert main(pack_args) == EXIT_ALLOWED
    digest = json.loads(capsys.readouterr().out)["sha256"]
    original = artifact.read_bytes()
    pins = ["--artifact", str(artifact), "--sha256", digest, "--application", "cli-v1"]
    assert main(["verify-artifact", *pins, "--pretty"]) == EXIT_ALLOWED
    assert json.loads(capsys.readouterr().out)["valid"]
    assert main(["check", *pins, "-r", str(allowed)]) == EXIT_ALLOWED
    assert json.loads(capsys.readouterr().out)["allowed"]
    assert main(["check", *pins, "-r", str(denied)]) == EXIT_DENIED
    assert not json.loads(capsys.readouterr().out)["allowed"]
    assert main(pack_args) == EXIT_INVALID
    assert capsys.readouterr().out == ""
    assert artifact.read_bytes() == original
    pins[3] = "0" * 64
    assert main(["verify-artifact", *pins]) == EXIT_INVALID
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("source", [["--artifact", "p"], ["--policy", "p", "--sha256", "0" * 64]])
def test_artifact_check_requires_complete_pins(source, capsys):
    with pytest.raises(SystemExit) as error:
        main(["check", *source, "-r", "r"])
    assert error.value.code == EXIT_INVALID
    assert capsys.readouterr().out == ""


def test_cli_batch_decisions_and_validation_atomicity(tmp_path, capsys):
    policy, allowed, _ = write_documents(tmp_path)
    request = json.loads(allowed.read_text())
    request["request_id"] = "one"
    batch = tmp_path / "batch.json"
    batch.write_text(json.dumps({"schema_version": 1, "requests": [request]}))
    args = ["batch", "-p", str(policy), "-b", str(batch), "--explain"]
    assert main(args) == EXIT_ALLOWED
    output = json.loads(capsys.readouterr().out)
    assert output["decisions"][0]["evaluations"]
    batch.write_text(json.dumps({"schema_version": 1, "requests": [request, {}]}))
    assert main(args) == EXIT_INVALID
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "batch.requests[1]" in captured.err
