# Competitive landscape and product wedge

Research refreshed August 8, 2026. This document records product decisions, not compatibility or
feature-parity claims.

## Recurring capabilities

| Product | Relevant official capability | Implication for Samsarix |
| --- | --- | --- |
| Open Policy Agent | [Policy tests](https://www.openpolicyagent.org/docs/policy-testing), signed and hot-reloaded [bundles](https://www.openpolicyagent.org/docs/management-bundles), and [decision logs](https://www.openpolicyagent.org/docs/management-decision-logs) | Executable expectations are table stakes; distribution and auditability become important when moving beyond one local process. |
| Cedar | A principal/action/resource/context request model, deny-overrides-allow authorization, and [schema-backed policy validation](https://docs.cedarpolicy.com/policies/validation.html) | Samsarix's small request model and strict schemas are a credible local wedge, but richer entity relationships are intentionally out of scope today. |
| Cerbos | Heterogeneous resource/action checks through [`CheckResources`](https://docs.cerbos.dev/cerbos/latest/api/index.html) and decision diagnostics/audit correlation | Batch evaluation is the next practical integration feature; audit output must remain opt-in and redactable. |
| OpenFGA | CI-friendly [authorization-model tests](https://openfga.dev/docs/modeling/testing) and pinned, [immutable model versions](https://openfga.dev/docs/getting-started/immutable-models) | Policy behavior and exact content identity should be pinned before deployment; a relationship graph is a different product category. |

## Chosen wedge

Samsarix should compete as a dependency-free embedded action guard for Python agents, automation,
developer tools, and small internal services—not as a smaller clone of a hosted authorization
control plane. Its useful constraints are deterministic local evaluation, strict bounded JSON,
default deny, explicit deny precedence, explainable decisions, and no network or runtime service.

The first competitive increment adds schema-validated executable policy suites and a real guarded
operation example. This improves policy authoring, CI safety, and consumer evidence without adding
a daemon, policy language runtime, database, or telemetry.

## Prioritized increments

1. **Executable policy suites and enforcement example** — implemented in the current increment.
2. **Bounded batch evaluation** — evaluate heterogeneous requests with stable per-item results and
   clear whole-batch validation/failure semantics.
3. **Versioned policy artifacts** — a manifest containing policy digest, application compatibility,
   and test evidence; signature verification only with a reviewed cryptographic dependency.
4. **Opt-in audit adapter** — caller-owned sink interface, explicit redaction, backpressure behavior,
   and correlation IDs; never silent telemetry.
5. **Consumer adapters** — framework-specific enforcement examples only after the core contracts are
   stable and each adapter has a side-effect-boundary integration test.

## Deliberate non-goals

Relationship tuple storage, identity lifecycle, remote policy administration, a general expression
language, and a hosted control plane require different operational and trust models. They should not
enter this package merely to lengthen a feature comparison. If a use case needs those capabilities,
OPA, Cedar-based systems, Cerbos, or OpenFGA may be the better fit.
