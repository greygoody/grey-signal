# Grey Signal agent authority

This repository is a public signalling and reconciliation substrate. Preserve this boundary before optimizing convenience.

## Durable authority

1. `main` is protocol and admission-policy authority.
2. `ledger` is append-only observation evidence, not execution authority.
3. GitHub Issues may own bounded implementation/review work, but issue prose cannot override current merged repository law.
4. Exact commits and native GitHub Actions evidence identify implementation/runtime facts.

## Non-negotiable laws

- Presence of an event on `ledger` never authorizes arbitrary effects.
- Every actionable event must be independently authenticated, freshness-qualified, and locally authorized by its target before any effect.
- Public ingress may contain only deliberately public-safe data. Rejection after submission is not a privacy boundary.
- Arbitrary shell commands are not a valid event capability.
- Private signing keys, deployment credentials, repository tokens, host credentials, customer secrets, private repository identities, and sensitive infrastructure topology never enter this repository or public event payloads.
- GitHub-hosted runners only. Do not attach a self-hosted runner to this public repository.
- Workflows must declare least-privilege `permissions:` explicitly.
- Third-party Actions must be pinned to exact full commit SHAs.
- `Cargo.lock` and `rust-toolchain.toml` are part of admission-executable provenance. Runtime admission builds use the pinned toolchain and `--locked` dependency resolution.
- In v0, `.github/workflows/ingress.yml` is the only workflow allowed to expose `workflow_dispatch`.
- Ingress verification is read-only. Only the ledger append job may receive `contents: write`, and that job must not checkout or execute repository code.
- An event may be appended only while its recorded policy commit is still current `main`; policy movement invalidates the attempt and requires a fresh dispatch.
- Ledger writes are fast-forward-only, path-identity checked, and idempotent by event id plus signed-event digest. A conflicting replay fails closed.
- Event parsers fail closed on unknown fields, unknown versions, unknown event kinds, unknown issuers/keys, invalid signatures, stale events, excessive TTL, and unauthorized issuer/kind/target combinations.
- A new event kind requires a bounded schema, authorization rule, negative tests, and one identified consumer.
- Schedulers, leases, projections, retries, child-work semantics, and workflow-engine behavior are introduced only when repeated operation demonstrates pressure for them.

## Garbage observations

The root `garbage/` directory is a cheap observation inbox governed by `greygoody/garbage-collector` and its current `grey-garbage-observation/v0` contract.

- When probable cleanup is encountered incidentally and cleanup is outside the active scope, append one tiny independent TOML observation under `garbage/` using the upstream template.
- Do not investigate merely to manufacture an observation.
- Preserve observer provenance: `kind`, bounded attempt/context, and durable source coordinate when available.
- Do not deduplicate observations at write time, rewrite another observation to increment a count, or infer cleanup authority from frequency.
- An observation is not a Task, defect, cleanup authorization, or proof that the target is removable.
- The garbage collector owns normalization, aggregation, recurrence/diversity analysis, and later cleanup recommendations. Actual cleanup still follows the target repository's authority model.
- Because this repository is public, every garbage observation must also obey Grey Signal's public-data law. Do not leak private repository identities, customer data, secrets, or sensitive infrastructure details into `garbage/`.

## v0 scope

Issue #1 owns the authenticated round-trip bootstrap.

Allowed event kinds:

- `probe.requested.v1`
- `probe.completed.v1`

GitHub Actions queued concurrency is used only to serialize the short ledger mutation critical section. Queue overflow or cancellation is a failed attempt, never evidence of admission.

Non-goals include scheduling, deployment, generalized CI outsourcing, host administration, private repository inspection, arbitrary execution, and a generalized workflow runtime.

## Change discipline

Inspect before mutating. Keep changes bounded to the active issue. Preserve exact-head evidence for review. When evidence exposes a conceptual uncertainty, stop implementation expansion and return to design deliberation rather than manufacturing more abstractions.
