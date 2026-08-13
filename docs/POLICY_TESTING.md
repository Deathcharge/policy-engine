# Policy testing

Policy tests are executable examples that pin the authorization behavior an application depends
on. Keep them beside the policy, review them with policy changes, and run them in CI before a
policy artifact is deployed.

## Test-suite format

A suite is a bounded strict-JSON object with a unique name and one to 1,000 named cases:

```json
{
  "$schema": "../policy_engine/schemas/test-suite.schema.json",
  "schema_version": 1,
  "name": "Document access contract",
  "cases": [
    {
      "name": "reader can view a public document",
      "request": {
        "principal": "user:alice",
        "action": "read",
        "resource": "document:public"
      },
      "expect": {
        "allowed": true,
        "reason": "explicit_allow",
        "matched_rule_ids": ["allow-read"]
      }
    }
  ]
}
```

`expect.allowed` is required. `reason` and `matched_rule_ids` are optional, but specifying them
protects more of the policy contract than checking the boolean alone. Matching rule IDs are
order-sensitive because policy rule order is stable and appears in decisions.

The bundled [test-suite schema](../policy_engine/schemas/test-suite.schema.json) is the editor-facing
contract. Runtime parsing additionally enforces strict UTF-8 JSON, duplicate-key rejection, the
1 MiB suite limit, unique case names, and normal request validation.

## CLI

```bash
samsarix-policy test --policy policy.json --suite policy-tests.json --pretty
```

The command prints one JSON report containing the policy digest, aggregate counts, each case's safe
decision, and assertion failures:

- exit `0`: every case passed;
- exit `1`: the suite was valid but at least one expectation failed;
- exit `2`: the command, policy, suite, or embedded request was invalid.

Test reports never echo request context values. They are suitable for CI artifacts, but they are not
production decision logs.

## Python API

```python
from policy_engine import PolicyEngine, load_policy, load_test_suite, run_test_suite

engine = PolicyEngine(load_policy("policy.json"))
report = run_test_suite(engine, load_test_suite("policy-tests.json"))
if not report.passed:
    for result in report.results:
        if not result.passed:
            print(result.name, *result.failures)
```

## Test design guidance

For each protected action, cover an explicit allow, an explicit deny where applicable, and the
default-deny path. Add boundary cases for production environments, missing approvals, sensitive
resources, and overlapping allow/deny rules. A suite proves the supplied examples; it does not
prove that a caller enforces decisions or that request attributes are truthful. Pair it with an
integration test at the actual side-effect boundary, as shown by the
[agent tool gateway](../examples/agent-tool-gateway/README.md).
