# Release runbook

This runbook prepares a reviewable artifact. Public publication is an owner action and must not be
performed until the legal and account gates below are complete.

## 1. Owner gates

- Confirm the BUSL-1.1 parameters in `LICENSE`, including the change date, 1,000-evaluation
  production-use grant, and Apache-2.0 change license. Keep the standard license body unchanged.
- Confirm that `samsarix-policy-engine` is controlled by Samsarix LLC on PyPI.
- Configure PyPI trusted publishing for the exact GitHub repository and a protected `pypi`
  environment. Do not store a long-lived PyPI token in the repository.
- Confirm `contact@samsarix.com` and `support@samsarix.com` are monitored.
- Obtain independent security and representative-user review for production adoption.

## 2. Prepare the version

Update the version in `pyproject.toml` and `policy_engine/__init__.py`, then turn the matching
`CHANGELOG.md` entry from `Unreleased` into a dated release. The test suite verifies that installed
distribution metadata and the public API version agree.

Run the complete gate from a clean checkout:

```bash
python -m venv .venv
python -m pip install -r requirements-dev.txt
python -m ruff format --check .
python -m ruff check .
python -m mypy policy_engine
python -m pytest --cov=policy_engine --cov-report=term-missing
python -m pip_audit --local --progress-spinner off
python -m build
python -m twine check dist/*
```

Inspect the wheel and source archive. They must contain the `policy_engine` package, all three JSON
schemas, typing marker, license, docs, examples, and tests; they must not contain credentials,
virtual environments, caches, build logs, or the historical `helix_core` extraction.

## 3. Exercise the artifact

Install the wheel into a new environment from outside the repository and reproduce the README
journey:

```bash
python -m venv wheel-smoke
wheel-smoke/bin/python -m pip install --no-deps dist/*.whl
wheel-smoke/bin/samsarix-policy --version
wheel-smoke/bin/samsarix-policy validate /absolute/path/to/examples/policy.json
wheel-smoke/bin/samsarix-policy check \
  --policy /absolute/path/to/examples/policy.json \
  --request /absolute/path/to/examples/request.allowed.json
```

Use `wheel-smoke\Scripts\` instead of `wheel-smoke/bin/` on Windows. Also verify the denied fixture
exits `3` and invalid input exits `2`.

## 4. Tag and stage

Create a signed `vX.Y.Z` tag only from the reviewed commit. The release workflow repeats the source
gates, checks that the tag and package versions match, builds from scratch, smoke-tests the wheel,
and retains the wheel and source archive as workflow artifacts for 14 days. A manual workflow run
can produce an unsigned candidate without creating a tag.

The workflow deliberately does not publish to PyPI. After the first artifact and license review,
add a separately protected publish job using PyPI trusted publishing, require approval on the
`pypi` environment, and publish the already-built artifact without rebuilding it.

## 5. Verify publication

After an authorized publication, install by exact version from PyPI in another clean environment,
repeat the allow/deny journey, confirm project metadata and links, create the GitHub release, and
record the result in `CHANGELOG.md`. Never overwrite or reuse a released version.
