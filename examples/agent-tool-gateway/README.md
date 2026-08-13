# Agent tool gateway

This example is a concrete enforcement point for an AI or automation agent. The caller constructs
an authorization request immediately before a side effect, evaluates it, and invokes the operation
only when the decision is allowed. A denial is not merely logged: the operation callback is never
called.

Run the executable policy contract:

```bash
samsarix-policy test \
  --policy examples/agent-tool-gateway/policy.json \
  --suite examples/agent-tool-gateway/policy-tests.json \
  --pretty
```

Exercise the allowed and denied paths:

```bash
python examples/agent-tool-gateway/demo.py search
python examples/agent-tool-gateway/demo.py shell
```

The search command exits `0` with `executed: true`. The shell command exits `3` with
`executed: false`; its callback deliberately raises if invoked, making an enforcement regression
visible in tests.

This is an integration pattern, not a sandbox. The embedding application remains responsible for
authentication, constructing truthful request attributes, protecting the policy file, and ensuring
there is no alternate path to the guarded operation.
