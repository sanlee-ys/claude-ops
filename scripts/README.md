# scripts

## redline-guard.py — the publication boundary, enforced

This repo is public **and canonical** ([ADR-002](../decisions/ADR-002-public-first-canonicality.md)):
material is written here first, so redaction happens at write time — which is
exactly where redaction mistakes happen. The guard scans every commit's staged
content for the [ADR-001](../decisions/ADR-001-public-claude-ops-repo.md)
boundary violations: credential-shaped strings, private repo names, employer
terms, private memory links, local user paths.

Install once per clone:

```
git config core.hooksPath scripts/githooks
```

Verify it actually blocks (the same decoy-file discipline the credential
guard's history demands — "the code looks right" is not the bar):

```
python -c "print('token: ghp_' + 'x'*24)" > decoy.md
git add decoy.md
git commit -m "should be blocked"   # expect: REDLINE GUARD refusal
git reset decoy.md && rm decoy.md
```

(The decoy is generated rather than written literally so this README itself
stays committable — a quoted example token would trip the very guard it
documents, which is how the credential guard's first over-broad draft died.)

Design notes, short version (long version in the script docstring and
ADR-002):

- **Identifying terms ship as SHA-256 hashes**, not literals — a guard that
  blocks private repo names can't have those names in its own public source.
- **Common-word collisions are context-gated.** Terms that are also ordinary
  English words only fire near "repo"/"repository"/"github"/"git" or inside
  an owner slug. A guard that blocks prose gets routed around.
- **Matches are echoed masked.** Printing the full matched string would be
  incident 1 all over again.
- **Override:** `REDLINE_OK=1` for one commit, consciously, with the reason
  in the commit message. **Local extensions:** an untracked `.redlines.local`
  (one term per line) adds terms without publishing them.
