# Helix Policy Engine

Helix Policy Engine is a small, local-first Python library and CLI for deciding whether an
agent or automation may perform an action on a resource. It evaluates structured JSON locally,
returns an explainable allow/deny decision, and has no runtime dependencies, network calls,
accounts, secrets, or LLM costs.

The project is an **alpha release candidate**. The core policy journey is implemented and tested;
the package has not been published to PyPI, and the existing license parameters need owner review
before a public release.

## Who it is for

It is for Python developers building local agents, CI automation, developer tools, or internal
services that need a lightweight guardrail at an action boundary. It is deliberately narrower than
a general-purpose policy platform such as OPA or Cedar: one process loads one bounded JSON policy
and makes deterministic decisions without another service or policy language runtime.

## Quick start

Prerequisite: Python 3.11, 3.12, 3.13, or 3.14.

```bash
git clone https://github.com/Deathcharge/policy-engine.git
cd policy-engine
python -m venv .venv
```

Activate the environment:

```bash
# macOS/Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Install the local package and run the included decision:

```bash
python -m pip install -e .
helix-policy validate examples/policy.json
helix-policy check --policy examples/policy.json --request examples/request.allowed.json --pretty
```

The allowed example exits `0` and prints a JSON decision. The denied example prints a denial and
exits `3`:

```bash
helix-policy check --policy examples/policy.json --request examples/request.denied.json --explain
```

Invalid policy, request, or command input exits `2` and writes structured JSON to stderr. This
makes the CLI predictable in shell scripts without conflating a policy denial with an execution
failure.

## Policy example

Policies use deny-overrides-allow semantics. No matching rule means `deny` unless the policy
explicitly selects a different default.

```json
{
  "schema_version": 1,
  "id": "agent-files",
  "default": "deny",
  "rules": [
    {
      "id": "allow-approved-scratch-write",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["file.write"],
      "resources": ["workspace/scratch/*"],
      "when": {
        "approved": {"equals": true},
        "environment": {"equals": "development"}
      }
    },
    {
      "id": "deny-secrets",
      "effect": "deny",
      "actions": ["file.*"],
      "resources": ["*.env", "secrets/*", "*/secrets/*"]
    }
  ]
}
```

Only `*` is special in principal, action, and resource patterns. It matches zero or more
characters; regex metacharacters have no special meaning. Conditions are ANDed and use dotted
paths under the request's `context` object. See [Policy format](docs/POLICY_FORMAT.md) for the full
contract and [the bundled JSON Schema](policy_engine/schemas/policy.schema.json) for editor support.

## Python API

```python
from policy_engine import PolicyEngine, load_policy

engine = PolicyEngine(load_policy("examples/policy.json"))
decision = engine.evaluate(
    {
        "principal": "agent:docs",
        "action": "file.read",
        "resource": "workspace/public/README.md",
        "context": {"environment": "development"},
    },
    explain=True,
)

if decision.allowed:
    perform_action()
else:
    raise PermissionError(decision.reason)
```

Policy evaluation is side-effect free. The returned `Decision` contains the policy ID and digest,
an optional caller-provided request ID, matching rule IDs, and (when requested) a trace of
which fields did not match. It does not echo context values into the trace.

## CLI reference

```text
helix-policy --help
helix-policy --version
helix-policy validate POLICY [--pretty]
helix-policy check --policy POLICY --request REQUEST|-
                   [--explain] [--pretty]
```

Use `--request -` to read a request from stdin. Policy files are limited to 1 MiB, request files
to 256 KiB, policies to 512 rules, and JSON nesting and value counts are bounded. Unknown fields,
duplicate JSON keys, non-finite numbers, and unsupported operators are rejected before evaluation.

## Development and verification

```bash
python -m pip install -r requirements-dev.txt
python -m ruff format --check .
python -m ruff check .
python -m mypy policy_engine
python -m pytest --cov=policy_engine --cov-report=term-missing
python -m build
python -m twine check dist/*
```

CI runs the same meaningful checks across supported Python versions. A wheel-install smoke test is
also part of release verification. The runtime intentionally has no third-party dependencies, so
there is no application dependency lockfile; development tools are constrained in the `dev` extra.

## Architecture

The enforcement point creates a request and calls `PolicyEngine.evaluate`. Strict loading and
validation happen before the immutable policy reaches the evaluator. Rule scope and conditions are
evaluated without `eval`, regex, plugins, I/O, or network access. Matching deny rules override
matching allow rules, then the configured default supplies the result when nothing matches.

The historical `helix_core` extraction that previously occupied this repository was not packaged,
depended on private `apps.backend` modules, and did not implement policy management. It is excluded
from this product; Git history retains it at commit `da2029a` for provenance.

## Security, privacy, reliability, and cost

- Treat the engine as a decision point, not an enforcement mechanism: the caller must check the
  decision before performing the action.
- Policies and requests are untrusted input and are validated with bounded resource use.
- Default-deny is the secure default, and explicit deny overrides allow.
- The engine stores nothing, transmits nothing, and logs no request or context values.
- Policy digests identify content but are not signatures; authenticate policy distribution in the
  embedding system when tamper resistance matters.
- Evaluation has no external API or operating cost beyond local CPU and memory.

See [SECURITY.md](SECURITY.md) for the trust boundary and responsible-reporting guidance.

## Limitations and deliberate non-goals

- Version 1 is an action guardrail, not an identity provider, authentication system, hosted policy
  service, policy editor, database, or complete RBAC/ABAC platform.
- Conditions do not execute code, call external data sources, traverse arrays by path, or support
  regex. These constraints keep evaluation reviewable and bounded.
- Policies are loaded explicitly. Hot reload, signing, remote bundles, and decision-log sinks remain
  embedding concerns.
- `default: "allow"` exists for migration scenarios but should be chosen deliberately.

## Contributing and release status

See [CONTRIBUTING.md](CONTRIBUTING.md) for the verified workflow and
[docs/PRODUCTIZATION.md](docs/PRODUCTIZATION.md) for the assessment, acceptance criteria, remaining
work, and release disposition. Version history is recorded in [CHANGELOG.md](CHANGELOG.md).

## License

The repository contains a customized Business Source License 1.1 with a change date of June 16,
2027 and Apache License 2.0 as its change license. The license file currently names “Helix Licensing
System” rather than this product; only the owner or legal counsel should correct those parameters.
Review [LICENSE](LICENSE) before use, especially the production-use threshold and commercial terms.
