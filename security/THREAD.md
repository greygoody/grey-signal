# Grey Signal security consideration thread

Security passes append or refine compact entries here. Keep provenance and disposition visible. Entries are security evidence and design pressure, not authority by themselves.

## SEC-0001 — Public traffic metadata is observable

**Disposition:** `ACCEPTED_RISK`

**Observed by:** `chatgpt / bootstrap-security-pass / 2026-08-30`

**Source:** user-supplied independent security review during Issue #1 bootstrap.

### Concern

Grey Signal can minimize or omit sensitive event content, but a public workflow and public ledger do not provide traffic confidentiality. Public observers may infer signal timestamps, event volume, retry patterns, producer/key counts, event kinds, target relationships, and correlation structure even when producer and target identifiers are opaque.

### Current v0 disposition

Accept this limitation for the bounded bootstrap rather than adding encryption or a private durable transport before evidence requires it.

Current mitigations:

- keep producer, target, event, and correlation identifiers random and opaque;
- never publish a mapping from opaque identifiers to private repositories, hosts, customers, or topology;
- keep payloads deliberately content-poor;
- use generic capability names whose existence is safe to reveal;
- preserve the existing public-data law before dispatch.

### Revisit trigger

Re-evaluate after the planned real round-trip experiment, or earlier if observed traffic patterns reveal sensitive relationships, event kinds themselves become sensitive, or traffic confidentiality becomes an explicit requirement.

If the risk becomes consequential, promote it through the normal Issue/PR path. Candidate responses may include encrypted payloads or moving durable ledger evidence behind a private boundary; neither is authorized by this note.
