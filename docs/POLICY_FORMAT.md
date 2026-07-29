# Policy format version 1

Samsarix Policy Engine evaluates one JSON policy against requests shaped as principal, action,
resource, and context. Version 1 intentionally favors a small, auditable grammar over an embedded
programming language.

## Resolution algorithm

Every rule is evaluated independently:

1. `principals`, `actions`, and `resources` must each match the corresponding request field.
2. Every entry in `when` must evaluate to true.
3. If any matching rule has `effect: "deny"`, the decision is deny.
4. Otherwise, if any matching rule has `effect: "allow"`, the decision is allow.
5. Otherwise, the top-level `default` applies. An omitted default is deny.

This is default-deny with deny-overrides-allow, the same broad resolution posture used by mature
authorization engines such as [Cedar](https://docs.cedarpolicy.com/auth/authorization.html). Unlike
Cedar or [OPA](https://www.openpolicyagent.org/docs), this product is limited to local action
guardrails and does not attempt to provide a general policy language or hosted decision service.

## Top-level fields

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | yes | Integer `1`. Unknown versions are rejected. |
| `id` | yes | Stable policy identifier. |
| `description` | no | Human-readable documentation. |
| `default` | no | `deny` (default) or `allow`. |
| `rules` | yes | Up to 512 rule objects; an empty list is a valid deny-all policy. |
| `$schema` | no | Editor hint, ignored during evaluation. |

Unknown fields are rejected so misspellings cannot silently weaken policy.

## Rules

Each rule requires a unique `id`, `effect`, non-empty `actions`, and non-empty `resources`.
`principals` defaults to `["*"]`. Each scope list accepts at most 64 strings.

Only `*` is a wildcard. It matches zero or more characters. Matching is case-sensitive and spans
separators such as `/` and `:`. Characters such as `.`, `?`, `[`, and `]` are literal.

```json
{
  "id": "allow-read",
  "description": "Documentation agents may read public files.",
  "effect": "allow",
  "principals": ["agent:docs-*"],
  "actions": ["file.read"],
  "resources": ["workspace/public/*"]
}
```

## Conditions

`when` maps a dotted path under request `context` to exactly one operator. Conditions in a rule are
ANDed. Paths traverse objects only; array indexing is not supported.

| Operator | Expected value | Behavior |
| --- | --- | --- |
| `equals` | scalar | Strict JSON equality; booleans are not numbers. |
| `not_equals` | scalar | Negated strict equality. Missing paths do not match. |
| `in` | non-empty scalar array | Actual value equals one listed value. |
| `not_in` | non-empty scalar array | Actual value equals no listed value. |
| `contains` | scalar | Actual value is an array containing the value. |
| `exists` | boolean | Path presence equals the supplied boolean. |
| `lt`, `lte`, `gt`, `gte` | number | Numeric comparison; booleans and strings do not coerce. |

```json
"when": {
  "approved": {"equals": true},
  "identity.roles": {"contains": "operator"},
  "risk.score": {"lte": 40}
}
```

Except for `exists: false`, a missing path fails its condition. Values are never coerced.

## Request format

```json
{
  "request_id": "optional-caller-trace-id",
  "principal": "agent:docs-1",
  "action": "file.read",
  "resource": "workspace/public/README.md",
  "context": {
    "approved": true,
    "identity": {"roles": ["operator"]},
    "risk": {"score": 10}
  }
}
```

`principal`, `action`, and `resource` are required non-empty strings. `context` defaults to an
empty object. `request_id` is optional and remains `null` in the decision when omitted. Supplying a
non-sensitive correlation ID is the caller's responsibility.

## Decision contract

Every successful evaluation returns `allowed`, `effect`, `reason`, policy identity and digest,
request identity, and the matching allow and deny rule IDs. `--explain` adds one record per rule
with its match state and the names of mismatching fields. Context values are not echoed.

The reason is one of `explicit_allow`, `explicit_deny`, `default_allow`, or `default_deny`.

## Limits and schema

Policies are limited to 1 MiB and requests to 256 KiB. Parsed JSON is limited to 16 levels,
10,000 values, finite numbers, bounded strings, 512 rules, and 64 scope patterns per field.
Duplicate JSON keys are rejected.

The bundled [policy](../policy_engine/schemas/policy.schema.json),
[request](../policy_engine/schemas/request.schema.json), and
[decision](../policy_engine/schemas/decision.schema.json) schemas follow JSON Schema Draft 2020-12
and mirror the public structural contracts. Runtime validation remains authoritative because it
also enforces unique rule IDs, byte limits, duplicate-key rejection, and resource bounds.
