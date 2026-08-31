# Competitive landscape and product wedge

Research refreshed August 31, 2026 (OPA bundles and OpenFGA immutable-model guidance rechecked).
This document records product decisions, not compatibility or
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

1. **Executable policy suites and enforcement example** — implemented.
2. **Bounded batch evaluation** — implemented; evaluate heterogeneous requests with stable per-item results and
   clear whole-batch validation/failure semantics.
3. **Versioned policy artifacts** — implemented: full manifest digest, exact application contract,
   revision, and optional passing-test evidence; trusted pins required for deployment loading.
4. **Opt-in audit adapter** — implemented: minimized events, synchronous caller-owned sink,
   fail-closed delivery, and opt-in correlation IDs; no silent telemetry.
5. **Consumer adapters** — the pinned file gateway proves a real local side-effect boundary.
   Framework-specific adapters remain demand-driven; no dependency-heavy web framework is required.

## Deliberate non-goals

Relationship tuple storage, identity lifecycle, remote policy administration, a general expression
language, and a hosted control plane require different operational and trust models. They should not
enter this package merely to lengthen a feature comparison. If a use case needs those capabilities,
OPA, Cedar-based systems, Cerbos, or OpenFGA may be the better fit.
