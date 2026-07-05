# Postmortem: GitHub PAT exposed again — same failure mode, fourth time, new tool shape

**Date:** 2026-07-04 | **Duration:** instant (two tool calls) | **Severity:** SEV2 (real credential exposed, no confirmed misuse)
**Status:** Resolved

## Summary

While auditing why an MCP subprocess was flashing a console window, Claude
used the **Read** and **Grep** tools (not Bash/PowerShell) to inspect
`~/.claude.json` for the MCP server config. That file holds a correctly-scoped,
working stdio `github` server — including its live PAT in
`mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN`. Both tool calls printed
the token in the clear to the session transcript. Same failure shape as the
three incidents in incidents/2026-07-03-github-pat-plaintext-recurrence.md, a
fourth time in two days — this time via a tool-coverage gap, not a
command-shape gap.

## Impact

- A live, correctly-scoped GitHub fine-grained PAT (`ghp_<REDACTED>`, the
  2026-07-04 stdio replacement — Contents:Read + PR/Issues:RW) printed to the
  transcript twice.
- The `github` MCP server entry itself is not the problem and was **not**
  removed — it's the legitimate fix from the prior incident. Only the token
  value needed rotating.
- No confirmed misuse.

## Root cause (5 whys)

1. Why did the token print? → `Read` on `~/.claude.json`, then `Grep` on the
   same file with `output_mode=content`, both showed the literal file content
   including the token.
2. Why did the credential-guard hook not block it? → The hook's `main()`
   opened with `if tool_name not in ("Bash", "PowerShell"): sys.exit(0)`. It
   only ever inspected Bash/PowerShell `tool_input.command` strings — Read
   and Grep pass `file_path`/`path` fields instead, which the hook never
   looked at.
3. Why wasn't this covered already? → The hook was built to close the
   *command-shape* gap (`cat`, `printenv`, `claude mcp get`) after the first
   three leaks all went through a shell command. Nobody had yet hit the
   *tool-shape* gap: Claude's own Read/Grep tools reading the same sensitive
   files without going through a shell at all.
4. Why did Grep in particular leak the value, when "grep for the specific key
   instead of catting the file" was the standing advice from the prior
   incident? → That advice assumed content-mode grep, which prints the
   matched line — and the matched line for a `"KEY": "value"` config entry
   *is* the secret. Only `files_with_matches`/`count` mode is actually safe;
   content mode is not, regardless of how narrow the pattern is.
5. Root cause: the mechanical guard covered every command shape seen so far,
   but was scoped to two tool names (`Bash`, `PowerShell`) out of several that
   can read file content. A guard keyed on tool name is only as complete as
   the enumeration of tools that can expose content — Read and Grep were not
   on that list.

## What went well

- Caught and flagged in the same turn it happened, same as all three prior
  incidents.
- Correctly distinguished "this config entry is fine" from "this printed
  value is compromised" — didn't repeat the earlier mistake of proposing to
  rip out a correctly-scoped, already-fixed integration.
- The credential-touching remediation (rotate + re-register) was handed back
  to the operator to run in their own terminal, per the standing protocol
  from the prior MCP integration work — no Claude tool call touched the new
  token.
- The fix was verified live against a harmless decoy file
  (`credentials-test.json` with a fake value) before declaring it working,
  rather than trusting the code read alone — same discipline as an earlier
  win's "status output isn't the bar."

## Fixes applied (2026-07-04)

| Fix | What | Where |
|---|---|---|
| Extended the guard to Read | Blocks any `Read` whose `file_path` matches the existing sensitive-file pattern | `security/credential-guard.py` |
| Extended the guard to content-mode Grep | Blocks `Grep` when `output_mode == "content"` and `path` matches the sensitive-file pattern; `files_with_matches`/`count` stay allowed (never echo the matched line) | `security/credential-guard.py` |
| Wired the new matchers | Added `Read` and `Grep` PreToolUse matchers pointing at the same hook script | Committed to a private config repo (settings templates + the live machine config), so fresh-machine provisioning gets it too |
| Synced live deploy | Copied the updated hook to the local hooks directory on this machine | This machine |
| Smoke-tested before commit | Created a decoy `credentials-test.json` with a fake value; confirmed `Read` and content-mode `Grep` both blocked, `files_with_matches` mode still passed, then deleted the decoy | This machine |
| Committed + pushed | Committed to the private config repo's main branch | Private config repo |
| Token rotated | Revoke old PAT, remove the MCP server registration, re-add it with a new token — run by the operator directly in their own terminal (never through a Claude tool call) | User-performed |

## Lessons learned

A mechanical guard's coverage is bounded by the surface someone thought to
enumerate — this is the same lesson incidents/2026-07-03-github-pat-plaintext-recurrence.md
already drew from its `claude mcp get` addendum, and it recurred at a
different layer: not a new command shape within an already-covered tool, but
a whole tool category (Claude's own file-reading tools) that was never in
scope. The actionable version going forward: any time a new hook is written
to block "reading X," ask "which *tools*, not just which *commands*, can read
X" — Bash/PowerShell aren't the only way a file's content reaches the
transcript.

Second lesson, specific to this incident: "grep instead of cat" is not
automatically safe. It's only safe in `files_with_matches`/`count` mode. A
targeted content-mode grep for a credential's key name still prints the
value, because the value lives on the same line as the key in essentially
every config format in use here (JSON, `.env`, YAML). The safe pattern is
"check existence with grep, don't retrieve content with grep" — narrowing the
*pattern* doesn't help if the *mode* still echoes the line.
