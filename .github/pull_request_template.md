# User-facing outcome

Describe the concrete behavior changed and why it belongs in this product.

## Safety and compatibility

- [ ] I preserved deny-overrides-allow and secure defaults within the schema version.
- [ ] I bounded new input, collections, recursion, concurrency, or retries.
- [ ] I did not add telemetry, network calls, secret handling, or policy-supplied code execution.
- [ ] I documented any intentional public API, CLI, schema, or exit-code change.

## Verification

- [ ] `python -m ruff format --check .`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy policy_engine`
- [ ] `python -m pytest --cov=policy_engine --cov-report=term-missing`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`

List additional boundary or artifact checks and their actual outcomes.
