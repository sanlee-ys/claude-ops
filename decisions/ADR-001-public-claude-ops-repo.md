# ADR-001: A public home for the Claude operating layer

**Status:** Accepted — 2026-07-05
**Scope:** This repo. Repo-local ADR per the two-tier convention (cross-repo
decisions live in the public `architecture` repo as SYS-NNN; a SYS entry
pointing here is a follow-up, not part of this ADR).

## Context

The practice of running Claude Code as an engineering teammate grew into a
real subsystem inside a private repo: incident postmortems (four credential
exposures in one week, and the mechanical guard that ended them), permission
allowlist design, custom skills, and a written operating model. That work has
two audiences the private repo can't serve:

1. **Anyone running an agentic CLI with real credentials on their machine.**
   The failure modes documented here (env-var echo, config-file reads,
   interpreter bypasses, tool-shape gaps) are not specific to this setup —
   they match documented upstream issues and a wider plaintext-config problem
   in the MCP ecosystem.
2. **The portfolio.** Security posture for AI tooling is engineering work,
   and it should be inspectable like any other engineering work.

## Decision

Split the publishable layer into this public repo. Four pillars:

- `incidents/` — de-identified postmortems, blameless format, full 5-whys.
- `security/` — the credential-guard PreToolUse hook (published snapshot) and
  the layered posture it belongs to (allowlist design, escape hatches, the
  human-runs-credential-commands protocol).
- `skills/` — the global custom skills, published as patterns.
- `operating-model.md` — the working agreements: DCB (Direction / Contracts /
  Bar), session pre-flight, the parallel-session protocol.

## Boundaries (what never lands here)

- Credential values in any form, including revoked ones. Placeholders only.
- Names or contents of private repos. They are referred to generically
  ("a private strategy repo", "a private config repo").
- Employer internals: team names, internal decisions, and anything else
  about the day job beyond what a public résumé already carries. Employer
  name and generic skills are the ceiling.
- The raw permission allowlist file. The posture doc describes the design
  and its reasoning; the live `settings.json` is machine state, not content.

## Canonicality and sync

The private working copies remain the system of record — they carry
un-redacted detail (real repo names, commit hashes, timelines). This repo is
the **curated publication**, synced manually: a new incident is written
privately first, published here after de-identification. The hook snapshot
carries a `hook-version` header; the live deploy is provisioned from a
private config repo. Known tradeoff: dual-sourcing invites drift. Accepted
because the alternative — making the public copy canonical — would force
every private detail through a redaction step at write time, which is where
redaction mistakes happen.

## Why publish a security guard's internals?

Publishing `credential-guard.py` shows exactly which files and read
constructs it covers — including, implicitly, what it doesn't. Accepted:
the guard's value is defense-in-depth on a single user's machine, not
secrecy of its rules (an attacker with local execution has already won).
The postmortems are honest that each version of the guard was only as
complete as the surface someone thought to enumerate; publishing invites
the next gap to be found by a reader instead of a leak.
