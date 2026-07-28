# Productization record

Last updated: 2026-07-28

## Repository assessment

The repository was extracted from `helix-unified` in commit `da2029a` and then given generic
templates. Before productization it did not contain a policy engine. It contained 5,815 lines of an
unpackaged `helix_core` agent-runtime snapshot plus mutually inconsistent packaging:

- the root distribution was named `policy-engine` version `0.1.0` while the nested manifest was
  `helix-core` version `1.0.0`;
- `find_packages()` found no import package because `policy_engine/__init__.py` did not exist;
- installation depended on unavailable `helix-hub-shared>=0.1.0`;
- runtime imports referenced private `apps.backend` modules absent from this repository;
- `HelixRuntime` called `HelixCoreLLMBridge(provider=...)`, but the bridge accepted no arguments;
- `ucf.metrics` imported its base class from the absent monorepo at module import time;
- the requirements installed web, AI, database, Discord, Redis, Celery, and notebook stacks that
  were not needed by any standalone product journey;
- no tests, examples, docs directory, workflows, package entry point, or policy API existed;
- the README advertised all of those missing assets, claimed production readiness, and said MIT
  while the repository license is a customized Business Source License 1.1.

The historical extraction is recoverable from Git and is not part of the selected distribution.

## Product definition

**Samsarix Policy Engine** is a dependency-free Python library and CLI for local, deterministic action
guardrails. A developer loads a JSON policy, submits a principal/action/resource/context request,
and receives an explainable decision before their application performs the action.

Target user: a Python developer building an agent, CI automation, developer tool, or internal
service who needs a small embedded decision point without deploying a policy service.

Primary use case: validate a policy and gate one potentially sensitive agent action with a stable
decision contract and shell exit code.

Independent reason to exist: it provides a narrow embedded option for Samsarix and unrelated
Python tools. It has no dependency on the historical `helix-unified` codebase, private services,
LLM providers, credentials, or cloud infrastructure.

## Product and architecture decisions

- Python package plus CLI is the smallest useful product form.
- JSON is the only configuration format; YAML and executable policy formats are out of scope.
- Policies are immutable after validation.
- Default deny and deny-overrides-allow are the resolution model.
- Rule scope uses a bounded literal-segment `*` matcher instead of regex.
- Conditions use a fixed operator allowlist and typed comparisons without coercion.
- Decisions contain identifiers and mismatch field names, not request context values.
- Runtime dependencies are zero. Distribution is a wheel/sdist built from `pyproject.toml`.
- The package is named `samsarix-policy-engine`, module `policy_engine`, and CLI
  `samsarix-policy`.
- Schema version 1 is explicit; unknown versions and unknown fields fail validation.
- The obsolete `helix_core` extraction is removed from the product tree rather than supported as an
  accidental public API.

Bounded current research used primary documentation from OPA, Cedar, JSON Schema, and the Python
Packaging User Guide. The chosen design borrows mature default-deny, explicit-deny precedence,
structured diagnostics, JSON Schema Draft 2020-12, and console entry-point conventions while
remaining intentionally smaller than a general authorization language.

## Assumptions

- Repository and distribution renaming are allowed because no release tags or working install
  exist and the requested task prioritizes an honest standalone product.
- Python 3.11 is the minimum because the public model uses `StrEnum`; support is capped at the
  latest version exercised in CI (3.14) rather than being implied for untested future versions.
  The local verification environment is Python 3.11.9.
- The owner wants the existing license preserved, not replaced. Metadata may identify its SPDX
  family, but legal parameters remain owner-controlled.
- Samsarix LLC is the licensor and copyright holder; `contact@samsarix.com` is the commercial
  contact and `support@samsarix.com` is the private support/security contact.
- Public package publication and production deployment are not authorized.

## Baseline command results

Run on Windows, Python 3.11.9, commit `f645501` before implementation:

| Command | Actual result |
| --- | --- |
| `git status --short --branch` | Clean tracked worktree on `main`; baseline tooling later created ignored cache files. |
| `.venv\\Scripts\\python -m pip install -e .` | Failed: no distribution satisfies `helix-hub-shared>=0.1.0`. |
| `python -m pytest -q` | Exit 5: `no tests ran in 0.11s`. |
| `python -m compileall -q policy_engine` | Completed before the next command; no syntax output. |
| `python -m mypy policy_engine` | Hung for more than four minutes and was terminated; no usable result. |
| `python -m build --no-isolation` | Failed: missing build dependency `wheel`; also reported conflicting/deprecated license metadata. |
| `python -c "import policy_engine"` | Loaded only a namespace package with `__file__ = None`. |
| `python -c "import helix_core"` | Failed with `ModuleNotFoundError`. |
| start command | None existed or was documented accurately. |

Final verification results are recorded below after they are run; this document does not treat
planned checks as passed.

## Findings

### P0

- [x] Installation depended on a nonexistent package.
- [x] No importable or published package surface existed.
- [x] No policy evaluation journey existed.
- [x] README setup, examples, docs, CI, license, and maturity claims were false.
- [x] Core extraction depended on missing private monorepo modules.
- [x] No tests protected behavior.

### P1

- [x] Remove unrelated runtime dependencies and external API/key paths from the product.
- [x] Add strict input validation, resource bounds, deny precedence, and safe errors.
- [x] Add stable CLI output and distinct denied/invalid exit codes.
- [x] Add unit, command, packaging, and primary-journey coverage.
- [x] Add CI, build metadata, changelog, security guidance, and accurate contribution steps.
- [x] Update the product identity, licensor, copyright holder, and working contact channels.
- [ ] Owner/legal review of the remaining customized license parameters.
- [x] Select `samsarix-policy-engine` as the intended public distribution name.

### P2

- [ ] Optional signed-policy verification adapter.
- [ ] Optional policy-set hot reload with atomic last-known-good behavior.
- [ ] Performance benchmark corpus for the 512-rule upper bound.
- [ ] More condition primitives only when validated user demand justifies the complexity.

## Implementation checklist

- [x] Schema-versioned policy and request models.
- [x] Strict bounded JSON loader.
- [x] Default-deny, deny-overrides-allow evaluator.
- [x] Fixed, typed condition grammar.
- [x] Bounded literal-segment wildcard matching.
- [x] Explainable decision contract without context-value echoing.
- [x] `validate` and `check` CLI commands.
- [x] Runnable allow and deny examples.
- [x] Public API documentation and policy-format reference.
- [x] Draft 2020-12 policy, request, and decision schemas with example validation.
- [x] Test suite and CI workflow.
- [x] Build and package configuration.
- [x] Pinned CI actions, dependency updates, candidate-artifact workflow, and release runbook.
- [x] Final verification and adversarial review.

## Release acceptance criteria

- Fresh local editable install succeeds with no runtime dependencies.
- README allow and deny commands reproduce the documented exit behavior.
- Format, lint, strict type check, tests with at least 90% branch coverage, build, package metadata,
  wheel install, and dependency audit pass.
- Malformed, oversized, duplicate-key, deep, and non-finite JSON fails safely.
- A matching deny overrides a matching allow; no match denies by default.
- The wheel contains the intended package, typing marker, and schema, but not legacy runtime code.
- CI runs meaningful checks on every push and pull request.
- Documentation contains no unverified feature, publication, or maturity claim.
- Owner-controlled release gates are named precisely.

## Completed work

- Defined and implemented the standalone embedded policy product.
- Replaced conflicting packaging and dependency templates with one modern manifest.
- Added the library, CLI, schema, examples, tests, and accurate documentation.
- Removed the broken agent-runtime extraction from the shipped product surface.
- Froze validated policy values so caller-owned input cannot mutate a live engine.
- Added bounded-input and malformed-input defenses, dependency auditing, and package smoke tests.
- Rebranded the pre-release product and command surface for Samsarix LLC.
- Added structured repository intake, maintenance automation, and a non-publishing release workflow.

## Deferred or blocked work

- **Owner/legal:** Confirm the June 16, 2027 change date, 1,000-call production-use threshold,
  California governing-law language, pricing terms, and whether this customized BUSL-1.1 remains
  the intended public license. Company, work, copyright, pricing-site, and contact identity now use
  Samsarix LLC.
- **Owner/release:** Reserve `samsarix-policy-engine` on PyPI, configure trusted publishing, and
  publish only after license review. Verify installation from the public artifact. The exact PyPI
  project endpoint returned 404 during the 2026-07-28 availability check, but that is not a
  reservation or guarantee.
- **Owner/portfolio:** Decide whether the old `helix_core` extraction should live in a separate
  archival repository. Git history is sufficient for this release candidate.
- **Owner/brand:** Choose or create the canonical Samsarix-owned GitHub repository. The working
  origin remains `Deathcharge/policy-engine`, while the Samsarix website's GitHub footer pointed to
  the obsolete `helix-collective/helix-unified` URL and returned 404 on 2026-07-28. Repository and
  schema URLs deliberately retain the working origin until a real replacement exists.
- **Owner/security:** Run an independent security review before a production rollout. The automated
  scanner is intentionally skipped per owner direction; the repository receives direct manual
  review, adversarial tests, dependency auditing, and bounded-input verification instead.

## Known risks

- Callers can ignore a denial; the engine cannot enforce an action boundary by itself.
- Local policy files can be tampered with unless the embedding application protects distribution.
- `default: "allow"` can create fail-open behavior and is retained only for deliberate migrations.
- Policy and request IDs may be sensitive operational metadata even though context values are not
  echoed.
- The product has not yet received independent security review or real-user validation.

## Distribution and sustainability

The simplest distribution is a pure-Python wheel installed into the embedding application or with
`pipx` for CLI use. No hosted service is required. A plausible sustainable model is an owner-funded
open-core developer component with paid integration/support or a commercially licensed hosted
management layer later. No demand, pricing viability, or product-market fit is claimed.

Runtime operating cost is local evaluation only: approximately proportional to
`rules × (scope patterns + conditions)`, bounded by the documented limits. There are no token,
model, network, storage, telemetry, or per-request vendor costs.

## Final verification

Run locally on Windows with Python 3.11.9 on 2026-07-28:

| Check | Actual outcome |
| --- | --- |
| `python -m ruff format --check .` | Passed; every discovered file was already formatted. |
| `python -m ruff check .` | Passed with no findings. |
| `python -m mypy policy_engine` | Passed in strict mode across 9 source files. |
| `python -m pytest --cov=policy_engine --cov-report=term-missing` | 77 passed; 90.62% branch-aware coverage; 90% gate passed. |
| `python -m compileall -q policy_engine tests` | Passed with no syntax errors. |
| remove predecessor metadata, then `python -m pip install -e ".[dev]"` | Branded editable metadata build and development install passed. |
| `python -m build` and `python -m twine check dist/*` | Built wheel and sdist; both metadata checks passed. |
| isolated Samsarix wheel install outside the repository | Version, import, all schema resources, validation, allow (`0`), deny (`3`), and invalid-command (`2`) checks passed; no legacy CLI was installed. |
| `python -m pip_audit --local --progress-spinner off` | No known vulnerabilities; the unpublished local project was explicitly skipped because it is absent from PyPI. |
| `git diff --check` plus adversarial marker/dynamic-execution searches | Passed; matches were limited to provenance documentation and the inert exception-class body. |

The engineering disposition is **release candidate**, not public-release approval. Public
publication remains blocked on the named owner/legal license decisions and PyPI setup, and
production use remains gated on independent security review and representative user validation.
