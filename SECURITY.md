# Security policy

## Supported versions

No public release has been made. Security fixes currently target the default branch and the pending
`0.1.x` release line.

## Reporting a vulnerability

Prefer GitHub's private vulnerability-reporting feature for this repository. If it is unavailable,
open a minimal issue asking the maintainer for a private reporting channel; do not publish exploit
details, credentials, private policy content, or personal data in a public issue.

## Trust boundary

Helix Policy Engine accepts untrusted JSON policy and request documents and returns a decision. It
does not authenticate principals, authorize access to the policy file itself, sign policies,
perform the requested action, or guarantee that its caller enforces the result. The embedding
application owns those controls.

The parser rejects duplicate object keys, non-finite numbers, unknown fields, malformed conditions,
and oversized or deeply nested documents. Evaluation supports only exact comparisons, bounded
numeric comparisons, list membership, dotted object paths, and a bounded `*` wildcard matcher.
It does not evaluate code, regex, templates, YAML tags, shell commands, or network data.

Decision explanations include identifiers and mismatch field names, not request context values.
Callers should still treat decisions and policy identifiers as potentially sensitive and apply
their own retention and access controls.

## Safe deployment guidance

- Keep `default` set to `deny` unless fail-open behavior is an explicit, reviewed requirement.
- Load policies from an authenticated, integrity-protected source in production.
- Evaluate immediately before the protected action and enforce every denial.
- Do not use a decision digest as a digital signature.
- Pin and review the package artifact used in a deployed system.
- Re-run representative allow and deny fixtures whenever a policy changes.
