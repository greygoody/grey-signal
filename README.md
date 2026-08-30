# grey-signal

Grey Signal is a small public signalling and reconciliation substrate.

Its job is deliberately narrow: authenticate public-safe event envelopes, admit them under an explicit protocol/policy revision, and provide durable observation evidence. It is not a scheduler, deployment authority, remote shell, workflow engine, or source of authority over a target host.

## Authority model

```text
producer transport credential
        |
        v
GitHub workflow ingress
        |
        v
producer signature verification
        |
        v
Grey Signal admission policy
        |
        v
append-only ledger evidence
        |
        v
target observes event
        |
        v
target-local authorization
        |
        v
bounded local effect (if allowed)
```

An admitted event proves that Grey Signal accepted an authenticated producer statement under a particular policy commit. It never means that a target must execute the requested capability.

## v0

Issue #1 owns the bootstrap specimen. v0 admits exactly two event kinds:

- `probe.requested.v1`
- `probe.completed.v1`

The first operational proof is one harmless signed request -> admission -> observation -> signed completion round trip.

## Branches

- `main`: protocol, admission policy, code, workflows, pinned dependency/toolchain provenance, and public producer registry.
- `ledger`: append-only admitted event records. It was forked from the pristine initial commit before executable workflow code was added to `main`.

`main` requires pull requests and the `rust` status check and rejects force-push/deletion. `ledger` rejects force-push/deletion. Those GitHub rules are part of the operational boundary, while Git history remains the evidence trail for every ledger mutation.

## Public-data rule

Everything submitted to Grey Signal ingress must already be safe to publish. Use opaque producer, target, correlation, and event identifiers. Never send repository names that are meant to remain private, customer identities, private branch names, internal paths, private hostnames/IPs, credentials, secrets, arbitrary commands, or secret-bearing payloads.

Admission rejects malformed or unauthorized protocol data, but privacy is a producer-side responsibility because GitHub receives the dispatch before Grey Signal can reject it.

## Ingress v0

`.github/workflows/ingress.yml` is the single externally dispatchable workflow. It accepts one base64url-encoded signed envelope through `workflow_dispatch`.

Transport permission and event authority are separate: a caller may be allowed to trigger the workflow, but the event is admitted only if its issuer/key signature and issuer/kind/target grant pass current `main` policy.

The verification job:

- runs only when dispatched against `main`;
- checks out the exact policy commit;
- builds with Rust 1.98.0 and committed `Cargo.lock` using `--locked`;
- receives only read repository permission;
- requalifies that `main` has not moved before and after admission.

The ledger append job receives the admitted record as data. It does not checkout or execute repository code. It alone receives `contents: write`, requalifies that the policy commit is still current `main`, checks event-id/digest replay identity, and creates `events/<event-id>.json` on `ledger` through the GitHub Contents API.

Same event id + same signed-event digest is an idempotent success. Same event id + different digest fails closed.

Ledger mutation is serialized with GitHub Actions queued concurrency (`queue: max`) so pending events are queued rather than replaced by newer pending runs. The queue is bounded; a cancelled, overflowed, expired, or failed workflow is not admission evidence and must be retried as a fresh producer attempt when appropriate.

## Event envelope v1

All fields are required; `causation_id` may be `null`.

```json
{
  "spec": "grey-signal/event/v1",
  "id": "evt_example",
  "issuer": "p_example",
  "key_id": "k1",
  "kind": "probe.requested.v1",
  "target": "t_example",
  "issued_at": "2026-08-30T17:30:00Z",
  "expires_at": "2026-08-30T17:40:00Z",
  "correlation_id": "cor_example",
  "causation_id": null,
  "payload": { "nonce": "opaque-random-value" },
  "signature": "BASE64URL_ED25519_SIGNATURE_WITHOUT_PADDING"
}
```

The signature covers the envelope with `signature` removed, encoded as compact JSON with object member names sorted lexicographically at every nesting level. Array order and string bytes are preserved. v0 payload schemas contain strings only, avoiding numeric canonicalization ambiguity.

Producer public keys and grants live under `registry/producers/`.
