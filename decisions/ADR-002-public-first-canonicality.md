# ADR-002: This repo is the system of record (public-first, mechanically guarded)

**Status:** Accepted — 2026-07-05. Supersedes the "Canonicality and sync"
section of [ADR-001](ADR-001-public-claude-ops-repo.md). The publication
boundaries in ADR-001 are unchanged and still authoritative.

## Context

ADR-001 made the private working copies the system of record and this repo a
curated, manually-synced publication. The stated reason: making the public
copy canonical forces every private detail through a redaction step at write
time, which is where redaction mistakes happen.

That reasoning didn't survive contact with this repo's own thesis. "Redact
carefully while writing" is a behavioral rule, and the incident series
documented here exists because behavioral rules that matter get mechanical
backstops or they eventually fail. The drift cost of dual-sourcing, on the
other hand, is permanent and structural: two copies of every postmortem,
each edit needing an "and the other copy" step — the exact failure mode
incident 6 in [posture.md](../security/posture.md) describes for the guard's
own bootstrap copy.

There was also a simpler point, made by the repo's owner: separation was the
purpose of this repo. A publication layer that can't hold the master copy
isn't separate; it's a mirror.

## Decision

1. **This repo is the system of record for the Claude operating layer.**
   New incidents, posture changes, skill updates, and operating-model changes
   are written here first, public-first.
2. **The redaction step gets a mechanical backstop:** a pre-commit redline
   guard ([scripts/redline-guard.py](../scripts/redline-guard.py)) that scans
   staged content for the ADR-001 boundary violations — credential-shaped
   strings, private repo names, employer-identifying terms, private memory
   links, local user paths. A redaction slip is caught at commit time instead
   of at push-shame time. If one ever gets through anyway, it gets logged in
   `incidents/` like any other failure.
3. **Private annexes are the exception, not the rule.** If an incident has
   detail that genuinely can't be public (a live hash, a token scope, a
   name), the public postmortem here is still the canonical record; the
   private annex holds only the redacted specifics, not a parallel copy.
4. **The credential-guard hook's canonical source moves here.**
   [security/credential-guard.py](../security/credential-guard.py) is now the
   master; the live deploy and machine-provisioning copies sync *from* this
   file. The `hook-version` header stays as the drift tripwire.

## Consequences

- Drift risk doesn't vanish — it reverses direction. The copies that can now
  go stale are machine state (the live hook, provisioning templates), which
  is rebuildable from this repo. The record itself no longer has a twin.
- Writing happens in public. The guard enforces the boundaries mechanically,
  but the *voice* discipline (blameless, de-identified by construction)
  becomes a habit rather than a post-hoc pass. That's the practice this repo
  documents anyway.
- The cross-repo registrations written under ADR-001's model (the system-tier
  entry, the private-repo pointers) said "private stays canonical" and were
  amended the same day this was accepted.

## The guard can't violate its own redlines

One design constraint worth recording: a guard that blocks private repo
names can't ship with those names written in its source, or the public file
becomes the disclosure. The guard therefore stores identifying terms as
SHA-256 hashes and compares tokenized words against them. Common English
words that happen to collide with private repo names are only flagged in
repo-shaped contexts (near "repo", "repository", an owner slug), because a
guard that blocks ordinary prose gets routed around — the same
false-positive lesson the credential guard's history teaches.
