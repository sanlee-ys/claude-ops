# scripts

## check-generated-drift.py — stale build output, caught in CI

For any repo that commits build output next to its source (a static site's
`index.html`, a generated SVG): rebuild from source, fail if the committed
output drifted. Generalizes learning-notes' repo-local `generated-files` job
per the [ADR-003 backlog disposition](../decisions/ADR-003-delegation-maturity.md).
The per-repo variables — build commands + watched paths — live in the consumer
repo's `.generated-drift.toml`:

```toml
[check.site]
build = ["python build_site.py", "python build_graph.py"]
watch = ["index.html", "concept-map.html", "assets/category-map.svg"]
```

Run locally from the consumer's root
(`python path/to/check-generated-drift.py`), or wire CI with one job via the
reusable workflow:

```yaml
jobs:
  generated-drift:
    uses: sanlee-ys/claude-ops/.github/workflows/generated-drift.yml@main
    # with:
    #   setup: pip install -r requirements.txt   # only if the build needs deps
```

Exit codes are the interface: 0 clean, 1 drift (rebuild and commit), 2
operator/config error (dirty watched path before the build, broken build
command, missing config). Test suite: `tests/test_generated_drift.py`.

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
