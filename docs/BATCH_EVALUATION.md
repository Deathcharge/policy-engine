# Bounded batch evaluation

Batch evaluation amortizes policy loading when a gateway, agent, or job must authorize several independent actions. The engine validates the complete document before evaluating any request.

```bash
samsarix-policy batch --policy examples/policy.json --batch examples/request.batch.json --pretty
```

Input contains 1–1,000 requests and is limited to 2 MiB. Every request needs a unique, non-null `request_id`; decisions retain input order. Malformed entries reject the whole batch with exit code `2`. A valid batch exits `0` even when individual decisions deny access; inspect each decision.

Library consumers call `parse_batch` or `load_batch`, then `evaluate_batch(engine, batch)`. Enable explanations only for diagnostics because output scales with request and rule counts. Enforce every decision immediately before its corresponding action.
