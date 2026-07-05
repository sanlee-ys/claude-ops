#!/usr/bin/env python3
# hook-version: 1 (canonical: the live deploy is provisioned from a private
# config repo; this file is the published snapshot)
"""Credential exposure guard (global PreToolUse hook).

Written 2026-07-03 after the SAME failure mode hit twice in one week:
2026-07-02 an ANTHROPIC_API_KEY got printed via an unmasked env-var debug
check; 2026-07-03 a GitHub PAT got printed via `cat ~/.claude/settings.json`.
Both postmortems (incidents/2026-07-02-plaintext-api-key-exposure.md,
incidents/2026-07-03-github-pat-plaintext-recurrence.md) adopted "never print a credential-shaped value unmasked" as a
*behavioral* rule for Claude. A behavioral rule that already failed twice
isn't a safety mechanism, it's a hope. This is the mechanical backstop.

Extended 2026-07-04 (incidents/2026-07-04-github-pat-read-grep-leak.md)
after a FOURTH leak of the same shape: this hook originally only matched on
`tool_name in ("Bash", "PowerShell")`, so reading `~/.claude.json` (the
correctly-scoped stdio `github` server's actual storage location) via the
**Read** or **Grep** tools sailed straight past it and printed the live PAT
to the transcript twice. Tool-shape coverage, not command-shape coverage,
was the gap this time - same lesson as the `claude mcp get` addendum,
recurring one layer down.

Extended again (found during a proactive security audit, not a live leak):
the Bash/PowerShell check previously matched on a literal list of read verbs
(`cat`/`type`/`Get-Content`/`gc`). `python`, `python3`, and `py` are in the
settings.json always-allow list and were never in that list, so
`python3 -c "open('~/.claude.json').read()"` sailed through untouched - same
bypass applies to `node -e`, `perl`, or `[System.IO.File]::ReadAllText(...)`.
Widened READ_INDICATORS to cover the common interpreter file-read APIs
(`open(`, `readFileSync(`, `ReadAllText(`, `.read()`, shell `<` redirection)
alongside the original four commands, still gated on an actual read
construct being present rather than just the filename appearing anywhere.
A first draft of this fix tried "block any mention of a sensitive path
unless it's a recognized existence-check verb," which is more thorough in
principle but immediately blocked its own commit message for quoting the
vulnerable example command in prose - false positives on documentation
defeat the guard as surely as a missed bypass does, so it was reverted in
favor of requiring a real read construct.

Also widened SENSITIVE_FILE_PATTERN beyond this project's own secrets to
cover common credential stores this box doesn't use yet but could:
~/.aws/credentials, ~/.aws/config, .npmrc, .netrc, .docker/config.json,
.kube/config, .pgpass, gcloud's application_default_credentials.json, and
the GitHub CLI's hosts.yml (belt-and-suspenders - gh's token itself lives
in the OS keyring, not that file, on this machine, but the file format
allows a plaintext oauth_token and shouldn't be trusted blindly).

Blocks:

  1. Bulk environment dumps via Bash/PowerShell: `env`, `printenv`,
     `Get-ChildItem Env:`, `dir env:`, `ls env:`, `Get-Item Env:*`. Check a
     specific var instead ([bool]$env:X, or a truncated first-N-chars read).
  2. Reading a whole known credential-store file in full - via Bash/
     PowerShell, by ANY means (shell builtins, coreutils, or an interpreter
     one-liner) **or** via the Read tool.
  3. `claude mcp get <name>` (Bash/PowerShell) - prints a registered
     server's stored env vars, including secrets, by design.
  4. Grep against one of the same sensitive files in `content` mode (the
     default `files_with_matches`/`count` modes never print the matched
     line, so they're safe - only `content` mode echoes the line the
     secret's value sits on, which is what happened here).

Override: add MASK-OK to a Bash/PowerShell command if a full unmasked read
is genuinely needed and you've considered the exposure (mirrors
fanout-guard.py's PREMIUM-OK pattern). Read/Grep calls have no free-text
command to carry that override - fall back to Bash/PowerShell with
MASK-OK for a deliberate secret audit instead.

Exit 0 = allow, exit 2 = block (stderr surfaced to the model). Fails open
on anything it can't parse - never wedge the tool on a malformed payload.
"""
import sys
import json
import re


SENSITIVE_FILE_PATTERN = re.compile(
    r"(^|[\s/\\'\"(),=:])("
    r"settings\.json"
    r"|\.claude\.json"
    r"|\.env(\.[a-z]+)?"
    r"|credentials.*\.json"
    r"|id_rsa\w*"
    r"|id_ed25519\w*"
    r"|[\w.-]+\.pem"
    r"|\.aws[/\\](credentials|config)"
    r"|\.npmrc"
    r"|\.netrc"
    r"|\.docker[/\\]config\.json"
    r"|\.kube[/\\]config"
    r"|\.pgpass"
    r"|application_default_credentials\.json"
    r"|GitHub CLI[/\\]hosts\.yml"
    r"|\.config[/\\]gh[/\\]hosts\.yml"
    r")\b",
    re.IGNORECASE,
)
ENV_DUMP_PATTERN = re.compile(
    r"\b(env|printenv)\b\s*$"
    r"|Get-ChildItem\s+(-Path\s+)?Env:\*?\s*$"
    r"|dir\s+env:\s*$"
    r"|ls\s+env:\s*$"
    r"|Get-Item\s+Env:\*",
    re.IGNORECASE,
)
MCP_GET_PATTERN = re.compile(r"\bclaude\s+mcp\s+get\b", re.IGNORECASE)

# Constructs that actually emit a file's content, across the shells and
# interpreters this box uses. Widened from the original cat/type/Get-Content/
# gc list to close the python/node/perl bypass - but still requires an actual
# read construct (not just the filename appearing anywhere), so prose that
# merely *mentions* a sensitive filename (a commit message documenting this
# very fix, a doc, an echo) doesn't trip it. An earlier draft of this fix
# flagged any mention at all and immediately blocked its own commit message
# for quoting the vulnerable example command - too aggressive; reverted to
# requiring a real read construct in the same segment.
READ_INDICATORS = re.compile(
    r"\b(cat|type|gc)\b"
    r"|\bGet-Content\b"
    r"|\bImport-Csv\b|\bImport-Content\b"
    r"|open\s*\("
    r"|readFileSync\s*\(|readFile\s*\("
    r"|ReadAllText\s*\(|ReadAllBytes\s*\(|ReadAllLines\s*\("
    r"|\.read\s*\(\)|\.readlines\s*\(\)"
    r"|<\s*['\"$]",
    re.IGNORECASE,
)


def block(message):
    """Write a block reason to stderr and exit with the hook's block code."""
    sys.stderr.write(message)
    sys.exit(2)


def segment_exposes_sensitive_content(seg):
    """Check whether a command segment both reads a file and names a sensitive path."""
    return bool(READ_INDICATORS.search(seg) and SENSITIVE_FILE_PATTERN.search(seg))


def main():
    """Run the PreToolUse hook: allow or block based on the tool call on stdin.

    Reads the PreToolUse JSON payload from stdin and inspects it by
    tool_name: Read and Grep calls against known credential-store files are
    blocked outright (Grep only in content output mode); Bash/PowerShell
    commands are split into segments and checked for environment dumps,
    sensitive-file reads via any shell or interpreter construct, and
    `claude mcp get`. Any other tool call is allowed. A command containing
    MASK-OK skips all Bash/PowerShell checks.

    Exits 0 to allow the tool call, or writes a reason to stderr and exits 2
    to block it. Also exits 0 (fails open) if stdin isn't valid JSON, so a
    malformed payload never wedges the tool.
    """
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if file_path and SENSITIVE_FILE_PATTERN.search(file_path):
            block(
                "CREDENTIAL GUARD: this reads a known credential-store file in full\n"
                "(settings.json / .claude.json / .env / credentials*.json / SSH keys /\n"
                "*.pem / cloud CLI credential files) via the Read tool. Same exposure as\n"
                "`cat`-ing it. Grep for the specific key with output_mode=files_with_matches\n"
                "to check existence, or use Bash with MASK-OK if a full audit read is\n"
                "genuinely needed.\n"
            )
        sys.exit(0)

    if tool_name == "Grep":
        path = tool_input.get("path", "")
        output_mode = tool_input.get("output_mode", "files_with_matches")
        if output_mode == "content" and path and SENSITIVE_FILE_PATTERN.search(path):
            block(
                "CREDENTIAL GUARD: content-mode Grep against a known credential-store\n"
                "file prints the full matched line - including the secret value sitting\n"
                "next to the key. Use output_mode=files_with_matches or count instead,\n"
                "or Bash with MASK-OK if you genuinely need the value.\n"
            )
        sys.exit(0)

    if tool_name not in ("Bash", "PowerShell"):
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    if "MASK-OK" in command:
        sys.exit(0)

    # Multi-line / multi-command scripts: check each logical line/segment.
    segments = re.split(r"[;\n]|&&|\|\|", command)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        if ENV_DUMP_PATTERN.search(seg):
            sys.stderr.write(
                "CREDENTIAL GUARD: this command dumps the entire environment.\n"
                "Any credential-shaped var (*_TOKEN, *_KEY, *_SECRET) currently set\n"
                "gets printed in the clear to this transcript. Check a specific var\n"
                "instead, e.g. `[bool]$env:VARNAME` or a truncated first-N-chars read.\n"
                "If a full dump is genuinely needed and you've weighed the exposure,\n"
                "re-invoke with MASK-OK in the command.\n"
            )
            sys.exit(2)

        if segment_exposes_sensitive_content(seg):
            sys.stderr.write(
                "CREDENTIAL GUARD: this command references a known credential-store\n"
                "file (settings.json / .claude.json / .env / credentials*.json / SSH\n"
                "keys / *.pem / cloud CLI credential files) in a way that isn't just an\n"
                "existence/metadata check. This covers `cat`/`type`/`Get-Content` AND any\n"
                "interpreter one-liner (python/node/perl/PowerShell .NET calls) that\n"
                "reads the file's bytes - this is exactly how the 2026-07 incidents\n"
                "happened. Grep for the specific key you need instead (files_with_matches\n"
                "mode), or re-invoke with MASK-OK if a full audit read is genuinely\n"
                "necessary.\n"
            )
            sys.exit(2)

        if MCP_GET_PATTERN.search(seg):
            sys.stderr.write(
                "CREDENTIAL GUARD: `claude mcp get <name>` prints that server's\n"
                "stored env vars (including secrets) in the clear. Use `claude mcp\n"
                "list` instead to check connection status without revealing values.\n"
                "If you genuinely need to see the stored value, re-invoke with\n"
                "MASK-OK in the command.\n"
            )
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
