# Changelog

This project follows Semantic Versioning once releases are tagged. Dates are intentionally omitted
until the owner publishes a release.

## 0.1.0 - Unreleased

### Added

- Dependency-free Python policy evaluation API.
- `samsarix-policy validate` and `samsarix-policy check` commands with stable exit codes.
- Strict, bounded JSON loading and schema-versioned policy validation.
- Default-deny and deny-overrides-allow rule resolution.
- Explainable decisions without echoing private context values.
- Immutable validated policy values that cannot be changed through caller-owned lists.
- Policy, request, decision, and policy-test JSON Schemas with validated examples.
- Schema-validated policy test suites, a stable test report API, and `samsarix-policy test` for CI.
- Correlation-safe batch evaluation for up to 1,000 requests through the API and CLI.
- Versioned policy artifacts with full SHA-256 manifest pins, application contracts, optional
  passing-suite evidence, and `pack` / `verify-artifact` / pinned `check` commands.
- Public fail-closed `guarded_call` and opt-in minimized audit events; actual pinned-file consumer.
- Self-contained offline schemas and automated wheel/sdist inventories plus installed journeys.
- Optional pyperf benchmark harness with 20 correctness-checked synthetic workloads, source/input
  fingerprints, explicit timing boundaries, and cross-platform runner verification.
- Direct Request construction now validates fields and bounded contexts before freezing; mixed-key
  batch errors remain structured; unpaired surrogates and integers over 4,096 bits are rejected.
- A regression-tested agent-tool enforcement example covering explicit allow, explicit deny,
  default deny, overlapping rules, environment boundaries, and approvals.
- Examples, tests, pinned CI, dependency maintenance, candidate-artifact automation, structured
  repository intake, and release documentation.

### Changed

- Product identity, distribution metadata, CLI, licensing contacts, and support guidance now use
  Samsarix Policy Engine and Samsarix LLC before the first public release.
- Request context is deeply detached and immutable, and explained zero-rule decisions now retain an
  explicit empty evaluation trace.
- Replaced the previously modified license body with standard BUSL-1.1 terms and expressed the
  existing production threshold as a 1,000-policy-evaluation monthly Additional Use Grant.

### Removed

- Unpackaged `helix_core` extraction and unrelated application dependencies from the shipped
  product surface. The original source remains recoverable from Git history.
