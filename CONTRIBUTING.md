# Contributing

Samsarix Policy Engine is an alpha project. Small, reviewable changes that preserve deterministic,
bounded, local evaluation are welcome.

## Setup

Python 3.11 through 3.14 is supported.

```bash
python -m venv .venv
```

Activate the environment, then install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

## Quality gate

Run every check before opening a pull request:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy policy_engine
python -m pytest --cov=policy_engine --cov-report=term-missing
python -m build
python -m twine check dist/*
```

New behavior needs tests for the allow, deny, invalid-input, and boundary cases it changes. Public
API changes must update the README, policy-format documentation, schema when applicable, and
changelog.

## Design constraints

- Keep the runtime dependency-free unless a dependency has a clear, documented product benefit.
- Never execute policy text as Python, shell, regex, templates, or another ambient code format.
- Preserve deny-overrides-allow and secure default behavior within a schema version.
- Bound new collections, recursion, input sizes, and retry or concurrency behavior.
- Do not log policy request context or introduce telemetry by default.
- Treat license parameters, public package publication, production deployment, and commercial
  terms as owner-controlled actions.

## Pull requests

Use a focused branch and conventional, descriptive commit messages. Explain the user-facing change,
security implications, and exact commands you ran. Do not include secrets or sensitive real-world
policy documents in issues, fixtures, or logs.
