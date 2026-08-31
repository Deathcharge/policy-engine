# Workload sizing and performance measurements

Use these measurements to characterize this embedded Python library on **your** application host.
They do not establish production capacity, an SLA, service tail latency, or parity with another
policy engine. The corpus is synthetic and public, not a production trace or customer workload.

## Run from a checkout or source archive

Use the activated environment from the README, then install optional maintainer tools:

```bash
python -m pip install -e ".[dev]"
python scripts/benchmark_policy.py --group gateway --fast -o gateway.json
python -m pyperf show gateway.json
python -m pyperf stats gateway.json
```

The development extra installs pyperf (and its platform-measurement dependency), not additional
runtime dependencies. The harness is in the source archive, not the runtime wheel, so run it from
a checkout or unpacked source archive. Use a **new** output filename; pyperf refuses to overwrite an
existing result. `--group` accepts `gateway`,
`scaling`, `batch`, or `all` (the default). Run with `--help` for pyperf's complete options.

For a more substantial run, omit `--fast`. pyperf calibrates loop counts, excludes warmups, runs
separate worker processes, and retains samples and machine/interpreter metadata in JSON. Its
stability warnings matter: a short run on a busy desktop is exploratory, not a reliable regression
claim. No system tuning, priority changes, networking, or CPU affinity changes are requested by
the harness; pyperf may use CPUs already isolated by the host. Where supported, add `--timeout 30`
to bound each worker, not the entire suite. pyperf 2.10's pipe timeout cannot run on Windows Python
3.11 (missing `os.set_blocking`); the harness rejects that combination with a setup message. Use
Python 3.12+ for that option, or a supervisor/job-level timeout as in CI (10 minutes per job).
Without either limit the benchmark has no hard wall-clock deadline. Ctrl+C stops the run;
an interrupted output is not evidence
of a complete corpus run. Do not use memory tracing and call the resulting time normal latency.

These choices follow pyperf's [benchmark methodology](https://pyperf.readthedocs.io/en/latest/run_benchmark.html)
and [runner options](https://pyperf.readthedocs.io/en/latest/runner.html). OPA's
[performance guidance](https://www.openpolicyagent.org/docs/policy-performance) also illustrates
why policy shape matters; the Samsarix corpus does not benchmark OPA or imply equivalent semantics.

## Exactly what is timed

All calls use the public API. Every selected operation is checked once before registration with
the timer. Tests additionally check the entire corpus, deterministic fingerprints, and rejection
of incorrect results. No policy/request loading, correctness assertion, or fixture generation is
included unless the workload explicitly names that operation.

| Workload | Shape and timed boundary |
| --- | --- |
| `gateway.construct_engine` | Validate an in-memory 8-rule policy and compute its digest; excludes disk/JSON decoding. |
| `gateway.parse_request` | Validate and freeze one in-memory mapping with nested context. |
| `gateway.mapping_allow`, `mapping_deny`, `mapping_default` | Reuse an engine, validate a fresh mapping on each call, and evaluate. The explicit-deny input also matches the allow rule. |
| `gateway.parsed_allow`, `parsed_explain` | Evaluate an already validated Request; explanation variant retains the full trace but does not serialize it. |
| `gateway.guard_no_audit`, `guard_audit_json` | Evaluate a parsed request and run a constant-return callback; audit variant also serializes the minimized event to JSON and discards it. No disk, network, or durable audit is simulated. |
| `gateway.guard_denied_audit_json` | Evaluate an overlapping deny, serialize audit, raise/catch ActionDenied, return its Decision; callback is not executed. |
| `scaling.parsed_16_rules`, `parsed_128_rules`, `parsed_512_rules` | Two relevant gateway rules plus nonmatching tenant rules; one parsed allow request, all rules evaluated. |
| `scaling.parsed_64_conditions` | A two-rule policy whose allow rule has 64 matching conditions. |
| `scaling.parsed_64_patterns` | A two-rule policy whose allow rule matches the last of 64 resource patterns. |
| `batch.evaluate_1`, `evaluate_100`, `evaluate_1000` | Prevalidated batch, 8 rules, alternating allow/overlapping-deny inputs (size 1 is allow only). Includes construction of all decisions and the batch result. |
| `batch.parse_100` | Validate/freeze/correlate 100 in-memory request mappings; no evaluation. |
| `batch.evaluate_explain_json_100` | Evaluate 100 parsed requests with full explanations and serialize the whole response to JSON. |

Times are **per named call**. Batch times are for the **whole batch**, not per decision. Dividing
by the request count gives an amortized cost, not single-request latency. Calibrated sample values
are averages over repeated calls; their percentiles are not production request p95/p99.
The benchmark includes normal Python call/loop overhead; nothing is subtracted as a guessed baseline.

## Compare like with like

```bash
python -m pyperf compare_to before.json after.json --table
```

Run both on the same quiet host, interpreter, power configuration, and pyperf version, with the
same group and settings. Alternate before/after runs and repeat before claiming a regression.
Confirm matching `corpus_version`, workload names, `workload_sha256`, and `harness_sha256` metadata.
`policy_engine_source_sha256` identifies the actually imported package's Python sources, including
when the checkout and installed wheel differ. Record the source commit or artifact hash separately;
a source fingerprint is content identity, not provenance attestation. The harness fingerprint is
the script's exact bytes, so line-ending changes can affect it. Changes to workload inputs, expected
semantics, or timing boundaries require a new corpus version and updated golden test.

Raw pyperf JSON may include hostname, executable paths, CPU details, and other host metadata.
Inspect/redact it before sharing. The harness does not collect real requests, secrets, or production
events, and does not upload results. Store local raw measurements outside Git (for example in `dist/`).

CI runs all corpus correctness tests and single-loop worker smoke checks on Linux and Windows.
These intentionally short runs can emit instability warnings. CI gates **execution and correctness**,
not nanosecond thresholds on shared runners; they must not be used as published speed claims.

## Initial local characterization (exploratory)

On August 31, 2026, the full v1 corpus completed on CPython 3.11.9, 64-bit Windows, with 8 logical
CPUs and `QueryPerformanceCounter` (100 ns reported resolution). The command used 3 worker processes,
3 measured values per process, 1 warmup, and a 30 ms minimum raw-value duration:

```bash
python scripts/benchmark_policy.py --processes 3 --values 3 --warmups 1 --min-time 0.03 -o dist/workloads-20260831-final.json
```

| Selected whole-call workload | Mean ± sample standard deviation (9 values) |
| --- | ---: |
| Construct 8-rule engine | 2.25 ms ± 0.06 ms |
| Evaluate parsed request, 8 rules | 107 µs ± 28 µs |
| Validate mapping and evaluate, 8 rules | 330 µs ± 59 µs |
| Evaluate parsed request, 512 rules | 9.57 ms ± 0.48 ms |
| Evaluate parsed request, 64 matching conditions | 426 µs ± 24 µs |
| Evaluate parsed request, last of 64 patterns | 164 µs ± 5 µs |
| Evaluate prevalidated 100-request batch | 19.5 ms ± 0.6 ms |
| Parse/validate 100-request batch | 35.8 ms ± 3.6 ms |
| Evaluate and serialize explanations for 100 requests | 25.7 ms ± 0.9 ms |
| Evaluate prevalidated 1,000-request batch | 198 ms ± 5 ms |

pyperf emitted stability warnings for multiple workloads: this desktop run did not meet its strict
criterion for a stable result. The differences illustrate the expected work boundaries and roughly
linear all-rule/all-request scans; they are **not** product latency claims, published baselines, or
capacity limits. Rerun on the actual deployment class with a quiet/tuned host before setting a budget.
The complete local JSON (not committed because it contains host metadata) had SHA-256
`f157cc37c7e6ad818790d0062258fda71eb210adfe0bfeb8a2429284ff44542b` and contained all 20
workloads. Its package-source fingerprint was
`9a56a5c8511d3b50cf0e762af55a15ded7c417856171998717c75a55b466f43f`; harness fingerprint was
`c7e8c9657633ec845df7126a891ead9b422e1d1d1ea4f97f0fb3109ebf785adb`. These are evidence for
that local run only, not authenticity or reproducible archive hashes.

## Application guidance and limits

- Construct and reuse one PolicyEngine per selected immutable policy. `decide` rebuilds it for
  one-shot convenience; it is not the repeated-request fast path.
- A reused Request avoids repeated validation only when its exact immutable attributes are still
  current and trusted. Rebuild requests when identity, resource state, context, or permissions change.
  Do not cache decisions based only on principal/action/resource or bypass validation for speed.
- The evaluator scans all rules and collects every match, including on explicit deny. Increasing
  rules, patterns, conditions, list lengths, or requested explanations can increase CPU and allocation.
- Batch evaluation is sequential, not parallel, atomic enforcement, or a server-side bulk endpoint.
  The maximum 1,000 requests and 512 rules are input ceilings, not recommended batch sizes or latency
  guarantees. Combined worst cases and large context/list values need application-specific testing.
- Explanation JSON size and audit durability may dominate actual integration cost. Add your own
  storage, transport, concurrency, cancellation, resource-state checks, and actual operation timing
  before making a production budget. Synchronous evaluation has no built-in deadline/cancellation.

Policy evaluation remains local CPU/memory work with no model/token/network fees. Benchmarking uses
synthetic non-production evaluations; no change to the existing license grant is implied.
