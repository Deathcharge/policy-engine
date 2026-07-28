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
- Policy, request, and decision JSON Schemas with validated examples.
- Examples, tests, pinned CI, dependency maintenance, candidate-artifact automation, structured
  repository intake, and release documentation.

### Changed

- Product identity, distribution metadata, CLI, licensing contacts, and support guidance now use
  Samsarix Policy Engine and Samsarix LLC before the first public release.

### Removed

- Unpackaged `helix_core` extraction and unrelated application dependencies from the shipped
  product surface. The original source remains recoverable from Git history.
