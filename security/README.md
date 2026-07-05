# credential-guard

A `PreToolUse` hook for Claude Code that blocks common ways a credential
ends up printed in the clear to a session transcript. It's a mechanical
backstop, not a policy document: the behavioral rule ("never print a
credential-shaped value unmasked") already failed twice before this existed.
See [`../posture.md`](../posture.md) for the reasoning behind treating this
as a hook rather than a habit, and [`../incidents/`](../incidents/) for the
specific leaks that shaped each revision.

## What it hooks

`PreToolUse`, matched against four tool shapes:

- **Bash** and **PowerShell** — command strings, split into segments and
  checked for env dumps, sensitive-file reads, and `claude mcp get`.
- **Read** — blocked outright if `file_path` matches a known credential-store
  pattern.
- **Grep** — blocked only when `output_mode` is `content` and `path` matches
  the same pattern. `files_with_matches` and `count` modes never echo the
  matched line, so they stay allowed.

Read and Grep coverage were added later than Bash/PowerShell — the hook
originally only checked `tool_name in ("Bash", "PowerShell")`, which meant
Claude's own file-reading tools could read a secret straight past it. See
`incidents/2026-07-04-github-pat-read-grep-leak.md`.

## What it blocks

1. **Bulk environment dumps** — `env`, `printenv`, `Get-ChildItem Env:`,
   `dir env:`, `ls env:`, `Get-Item Env:*`. Any credential-shaped variable
   currently set gets printed in the clear. Check a specific variable
   instead (`[bool]$env:VARNAME`, or a truncated read).
2. **Full reads of known credential-store files**, by any means — shell
   builtins (`cat`, `type`, `Get-Content`, `gc`), interpreter one-liners
   (`python -c "open(...).read()"`, `node -e`, `perl`, PowerShell's
   `[System.IO.File]::ReadAllText(...)`), or the Read tool directly. The
   guard checks for an actual read construct alongside the filename, not
   just the filename appearing anywhere — so a commit message or doc that
   merely *mentions* `settings.json` doesn't trip it.
3. **`claude mcp get <name>`** — prints a registered MCP server's stored
   environment variables, including secrets, by design. Use `claude mcp
   list` instead to check connection status without revealing values.
4. **Content-mode Grep** against the same sensitive files — the matched
   line for a `"KEY": "value"` config entry generally *is* the secret, so
   narrowing the search pattern doesn't help if the output mode still
   echoes the line.

The sensitive-file pattern covers this project's own secrets plus common
credential stores it doesn't necessarily use yet: `settings.json`,
`.claude.json`, `.env*`, `credentials*.json`, SSH private keys, `*.pem`,
`~/.aws/credentials`, `~/.aws/config`, `.npmrc`, `.netrc`,
`.docker/config.json`, `.kube/config`, `.pgpass`, gcloud's
`application_default_credentials.json`, and the GitHub CLI's `hosts.yml`.

## The MASK-OK escape hatch

Sometimes a full unmasked read is genuinely necessary — a deliberate secret
audit, for example. Add `MASK-OK` anywhere in a Bash or PowerShell command
to skip all checks for that command. There's no equivalent for Read or
Grep, since those tools don't carry a free-text command to put the marker
in — fall back to Bash/PowerShell with `MASK-OK` instead.

Exit code 0 allows the tool call; exit code 2 blocks it and surfaces the
message on stderr to the model. The hook fails open (exits 0) on anything
it can't parse, so a malformed payload never wedges the tool.

## Wiring it into settings.json

The hook is a single script invoked once per matching tool call via
stdin/stdout, the standard shape for a Claude Code `PreToolUse` hook. In
`settings.json`, add matcher entries under `hooks.PreToolUse` for each tool
name this guard should see — `Bash`, `PowerShell`, `Read`, and `Grep` — each
pointing its `command` at this script (e.g. `python3 /path/to/
credential-guard.py`). Consult Claude Code's own hooks documentation for the
exact matcher/command JSON shape, since that schema is versioned by the
harness, not by this repo.

## Verifying it: the decoy-file smoke test

Don't trust a code read alone — verify the guard actually blocks before
relying on it:

1. Create a harmless decoy file with a shape the pattern should match, e.g.
   `credentials-test.json` containing a fake, obviously-not-real value.
2. Try to read it through each covered path: `cat`/`Get-Content` in
   Bash/PowerShell, a Read tool call, and a content-mode Grep. Each should
   be blocked with the guard's message on stderr.
3. Confirm `files_with_matches`/`count`-mode Grep against the same file
   still succeeds — that mode is intentionally allowed.
4. Try a Bash/PowerShell read with `MASK-OK` in the command and confirm it
   goes through.
5. Delete the decoy file.

This is the same method used to verify each extension in
[`../incidents/`](../incidents/) before it was committed — a hook that looks
right on inspection but hasn't been exercised against a real blocked and
real allowed case isn't verified yet.
