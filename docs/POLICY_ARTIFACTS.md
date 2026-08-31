# Pinned artifacts and action enforcement

Use an artifact when a reviewed policy must move from CI to a particular application without
silently picking up a different revision. Everything runs locally; no signing key or service is
required. An artifact is **not a signature**. The expected hash must come from separately protected
deployment configuration, not from the downloaded artifact itself.

## Complete local journey

After installing this repository, run:

```bash
python examples/pinned_gateway.py
```

The demo tests the file policy, packages revision `files-r1`, pins it for `file-gateway-v1`, verifies
it, reads an actual temporary document through `guarded_call`, and rejects a secret-read callback.
Output includes the document text, `denied_operation_executed: false`, and two minimized audit
records. Temporary files are cleaned up. This is a local reference consumer, not production adoption.

To prepare an artifact for your own deployment (use a new output filename each time):

```bash
samsarix-policy pack --policy examples/policy.json --revision files-r1 --application file-gateway-v1 --suite examples/file-policy-tests.json --output policy.artifact.json
```

Record the `sha256` printed by this trusted build in protected deployment configuration. Then use
that 64-character value in place of `TRUSTED_SHA256`:

```text
samsarix-policy verify-artifact --artifact policy.artifact.json --sha256 TRUSTED_SHA256 --application file-gateway-v1
samsarix-policy check --artifact policy.artifact.json --sha256 TRUSTED_SHA256 --application file-gateway-v1 --request examples/request.allowed.json
```

`pack` never overwrites a file. Failed suites, invalid input, file errors, or pin mismatches exit `2`
without a decision on stdout. `verify-artifact` exits `0` on success; `check` retains allow `0` and
deny `3`. The packer's output file uses canonical ASCII JSON regardless of terminal encoding.
An interrupted write may leave an incomplete file: verification rejects it; retry at a new path.

## Contract and compatibility

- `schema_version: 1` describes the artifact envelope. The nested policy's schema version still
  describes rule grammar; neither field is a deployment revision.
- `revision` is a caller-assigned identifier (for example a Git commit or release label).
- `application` is an exact-match consumer contract identifier (for example `invoice-service-v2`).
  It is not an automatically inferred compatibility guarantee or version range.
- `policy` is the validated, normalized policy, including defaults and descriptions, excluding
  its editor-only `$schema`. Rule/pattern/list ordering is preserved; conditions are path-sorted.
- `tests` is null if no suite was supplied. Otherwise the builder executes every case and records
  suite name, case count, and full suite SHA-256. Requests and test case names are not embedded.
  Suite name and policy content can still be sensitive: treat artifacts as configuration data.
- `sha256` is the full SHA-256 of the manifest **without** its `sha256` field. It binds the policy,
  revision, application, canonicalization identifier, and test evidence together.
- `canonicalization: samsarix-json-v1` means Python JSON serialization with sorted object keys,
  `ensure_ascii=True`, `allow_nan=False`, and separators `(',', ':')`, encoded as ASCII without a
  newline. It is not RFC 8785/JCS. Numeric `1` and `1.0` can have different identities. Do not
  reimplement this format in another language without matching golden vectors.
- Artifacts are bounded to 2 MiB, including metadata. Existing policy limits still apply.
  `create_artifact` also enforces the serialized limit; `load_artifact` bounds its file read.

Parsing normalizes the nested policy before hashing; insignificant formatting, key order, and
equivalent omitted defaults do not change its identity. This is a content identity, not the hash of
the raw file. Existing decisions retain the backward-compatible 32-character `policy_digest`,
which does **not** include revision/application/evidence; do not substitute it for the artifact pin.

`parse_artifact` checks internal consistency only. `load_artifact(path, expected_sha256=...,
application=...)` additionally enforces trusted pins. An attacker can recompute an internal hash,
but cannot match a separately protected pin for different content. Suite metadata is a builder
claim, not independent attestation; verification does not rerun tests whose inputs are not shipped.
To roll back, explicitly restore a prior trusted pin and its reviewed artifact together. There is
no automatic newest-version selection, anti-rollback counter, hot reload, or signature verifier.

## Library enforcement and audit

```python
from policy_engine import PolicyEngine, guarded_call, load_artifact

artifact = load_artifact(path, expected_sha256=trusted_digest, application="file-gateway-v1")
engine = PolicyEngine(artifact.policy)
result = guarded_call(engine, request, operation, audit_sink=my_sink)
```

The sink receives an immutable `AuditEvent` **before** an allowed operation executes, and also on
denials. Its JSON contract has `schema_version: 1`, `event: policy_decision`, `allowed`, `reason`,
`policy_digest`, and `request_id` (null by default). Principal, action, resource, context, policy ID,
rule IDs, and mismatch paths are omitted. Set `include_request_id=True` only for safe correlation
IDs. A sink can serialize with `event.to_dict()`; there is no default log, file, network, or telemetry.

- Denial raises `ActionDenied` and never invokes the callback.
- Sink failure raises `AuditDeliveryError` and never invokes the callback. The original exception
  is chained for diagnostics; callers must avoid exposing sink error details to untrusted users.
- No sink means no audit I/O. A supplied sink is synchronous backpressure: caller-owned timeout,
  storage durability, retention, access control, and sink availability must be designed explicitly.
- The callback is called once on allow. Callback exceptions propagate without retries.
- A decision event is not an operation-success receipt or transaction. If exactly-once effects or
  durable audit are needed, the embedding application owns that transactional protocol.

Only trusted application code may construct request attributes, select callbacks, and map logical
resources to actual files/tools. Do not pass attacker-controlled paths directly to file APIs. The
library cannot protect operations that bypass the guard or changes to a resource after evaluation.

## Offline editor/integration schemas

```python
from policy_engine.schemas import schema_document

document = schema_document("artifact.schema.json")
# Optional integration dependency, not needed for runtime policy evaluation:
# jsonschema.Draft202012Validator(document).validate(artifact.to_dict())
```

`schema_document` bundles all references as local JSON pointers from package resources. It does not
fetch schema URLs. The six raw schema files retain logical `$id` values; those identifiers do not
promise hosted endpoints. Use the bundled document for offline validation. JSON Schema cannot
verify checksums, correlate unique batch IDs, or enforce every aggregate runtime limit; Python
parsers/loaders remain authoritative.
