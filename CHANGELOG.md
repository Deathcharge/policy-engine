# Changelog

This project follows Semantic Versioning once releases are tagged. Dates are intentionally omitted
until the owner publishes a release.

## 0.1.0 - Unreleased

### Added

- Dependency-free Python policy evaluation API.
- `helix-policy validate` and `helix-policy check` commands with stable exit codes.
- Strict, bounded JSON loading and schema-versioned policy validation.
- Default-deny and deny-overrides-allow rule resolution.
- Explainable decisions without echoing private context values.
- Immutable validated policy values that cannot be changed through caller-owned lists.
- Examples, JSON Schema, tests, CI, and release documentation.

### Removed

- Unpackaged `helix_core` extraction and unrelated application dependencies from the shipped
  product surface. The original source remains recoverable from Git history.
