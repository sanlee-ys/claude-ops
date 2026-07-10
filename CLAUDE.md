# CLAUDE.md

Guidance for AI agents working in **claude-ops** — the canonical home for the
Claude operating layer (see
[`decisions/ADR-002-public-first-canonicality.md`](decisions/ADR-002-public-first-canonicality.md)).

- **Operating model & session protocol:** [`operating-model.md`](operating-model.md).
- **Security posture & the credential guard:** [`security/posture.md`](security/posture.md),
  [`security/README.md`](security/README.md).
- **Shared cross-repo blocks** — single-sourced here, mirrored into sibling
  repos' `CLAUDE.md` as compressed pointers: [`conventions/`](conventions/).
  Propagate or drift-check with `python scripts/sync-shared-blocks.py [--check]`.
- **Stale-generated-file gate** — reusable CI check for repos that commit
  build output: [`scripts/check-generated-drift.py`](scripts/check-generated-drift.py)
  + the `workflow_call` wrapper in `.github/workflows/generated-drift.yml`
  (consumer wiring: [`scripts/README.md`](scripts/README.md)).
- **Delegation policy** — task classes × autonomy levels, each gated on a
  verifier: [`delegation-policy.md`](delegation-policy.md).
- **Decisions:** [`decisions/`](decisions/). **Incidents:** [`incidents/`](incidents/).

This repo is public and guarded by a pre-commit redline check
(`scripts/redline-guard.py`): no credentials, private-repo names, or local
user paths reach a commit.
