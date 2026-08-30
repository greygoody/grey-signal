# Grey Signal security consideration path

This directory is the durable security-thinking thread for Grey Signal.

It is not a second authority plane. `AGENTS.md`, protected `main`, protocol code, tests, and accepted repository changes remain authoritative. Security notes here are evidence, hypotheses, concerns, and dispositions that later agent passes may refine.

This setup creates a parallel repository path only. It does not establish a long-lived security branch.

## Write discipline

- Inspect `security/THREAD.md` when work touches ingress, authentication, signatures, workflow permissions, public-data exposure, ledger semantics, producer/consumer credentials, or target execution boundaries.
- When a security concern is encountered during bounded work, append or update a short thread entry instead of launching an unrelated redesign.
- Preserve provenance: identify the observing agent/pass and a durable source coordinate when available.
- Distinguish `OPEN`, `ACCEPTED_RISK`, `MITIGATED`, `SUPERSEDED`, and `REJECTED` dispositions.
- A thread entry is not repository law, a vulnerability claim, or implementation authority. Promote consequential findings through the repository's normal issue/PR/review path.
- Prefer observed evidence over speculative scoring. Repeated independent observations are useful evidence, not automatic priority.
- Everything here is public. Never record secrets, private repository identities, customer information, sensitive topology, or other non-public operational details.

`THREAD.md` is intentionally simple. If repeated use creates pressure for a more structured format, evolve it then rather than manufacturing a security bureaucracy in advance.
