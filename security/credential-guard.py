#!/usr/bin/env python3
# hook-version: 2 (canonical: THIS file, per decisions/ADR-002 — the live
# deploy at ~/.claude/hooks/ and any provisioning copies sync FROM here)
"""Credential exposure guard (global PreToolUse hook) — path-based default-deny.

v2 (2026-07-06, claude-ops decisions/ADR-003 Phase 1). v1 enumerated the *read
verbs* it knew about (cat / Get-Content / open() / a short list) and blocked
those. Every one of the four 2026-07 credential incidents was a shape v1's
author had not enumerated yet, so the guard trailed each leak by exactly one
incident:

  - 2026-07-02 plaintext-api-key-exposure  — a user-scoped env var read.
  - 2026-07-03 github-pat-plaintext-recurrence — `cat ~/.claude/settings.json`.
  - 2026-07-03 credential-guard-interpreter-bypass — `python3 -c open().read()`.
  - 2026-07-04 github-pat-read-grep-leak   — the Read / content-Grep *tools*.

A proactive taxonomy of the guard's own surface (decisions/ADR-003) found the
denylist still open at, among others: `head`/`tail`/`xxd`/`base64`/`strings`/
`jq`/`awk` (any pager or formatter that isn't `cat`), `env | grep TOKEN`,
`declare -p`, `/proc/self/environ`, and — the 07-04 lesson one tool-generation
on — *every* content-returning tool the hook doesn't name (MCP file readers,
notebook reads). An enumerated denylist cannot win that race; it only ever
lists the last leak's shape.

v2 inverts the default. The question is no longer "is this one of the read
verbs I listed?" but "does a sensitive target's content reach the caller,
unless this is a recognised *safe* operation?" Concretely:

  1. Any tool with a path-bearing field (file_path / path / notebook_path /
     uri / ...) reading a sensitive target is blocked — for ALL tools, not a
     hard-coded {Read, Grep} pair. A reader tool nobody has hooked yet is
     covered the day it appears (closes the 07-04 class structurally).
  2. Grep keeps its output-mode nuance: only `content` mode echoes the matched
     line, so `files_with_matches` / `count` stay allowed (they are the
     recommended existence check).
  3. Bash / PowerShell: a segment that names a sensitive path is blocked unless
     its leading command is on a small SAFE allowlist (metadata/existence,
     pure file management, string/echo, and version control). So `xxd`, `jq`,
     `base64`, `python3 -c`, and any unknown reader are denied by *default*;
     `git commit -m "... .env ..."`, `echo`, heredoc prose, `ls`, `rm`,
     `grep -l`, and `stat` are not. This is the false-positive discipline v1's
     first over-broad draft violated (it blocked its own commit message for
     quoting the example); requiring the sensitive path to sit in an actual
     command position, and treating VCS/echo/heredoc as safe, keeps prose
     committable.
  4. Bulk and targeted environment reads: `env`/`printenv`/`set`/`declare -p`/
     the PowerShell `Env:` dumps, AND a single credential-shaped variable being
     printed (`echo $ANTHROPIC_API_KEY`, `printenv GITHUB_TOKEN`,
     `[Environment]::GetEnvironmentVariable("...KEY")`) — the founding 07-02
     incident, which v1 never caught.

Deliberately OUT of scope, per the posture's threat model (non-adversarial
agent mistakes; anyone with local code-execution has already won — see
posture.md and decisions/ADR-001): copy-then-read laundering (`cp secret x;
cat x`), indirection through a script the guard can't see into (`source .env`
is caught because `source` is not a safe verb, but `bash leak.sh` is not),
wildcard / variable-assembled path names (`cat ~/.claud*.json`, `f=.env; cat
$f`) that no path-regex can resolve without matching innocent globs too, and
MASK-OK forgery. Those are contained by the permission allowlist (no `$(...)`,
no arbitrary shell control-flow) and by treating any credential that touches a
transcript as compromised and rotating it (posture Layer 4), not by this hook.
The adversarial test suite (tests/test_credential_guard.py) carries a case per
taxonomy shape, including the ones we consciously do not block, so the boundary
is asserted rather than assumed.

Override: add MASK-OK to a Bash/PowerShell command for a deliberate, considered
unmasked read (mirrors fanout-guard.py's PREMIUM-OK). Read/Grep/other tools
have no free-text field to carry it — fall back to Bash with MASK-OK.

Exit 0 = allow, exit 2 = block (stderr surfaced to the model). Fails OPEN on an
unparseable payload — a deliberate availability-over-strictness choice for a
guard whose threat model is honest mistakes, not a malformed-input attacker;
never wedge the tool on a payload it can't read.
"""
import sys
import json
import re


# --- Sensitive targets -----------------------------------------------------
# Widened from v1 per the ADR-003 taxonomy §B. The prefix group anchors a match
# to a path boundary (start, slash, quote, or common shell separators) so a
# bare `.env` or `'.npmrc'` still matches but `prevented`/`sevent` do not.
_PREFIX = r"(^|[\s/\\'\"(),=:@])"
SENSITIVE_FILE_PATTERN = re.compile(
    _PREFIX + r"("
    # Claude's own config (narrowed to the .claude tree — a random project's
    # settings.json is not a credential store, and blocking it is a false
    # positive that erodes the guard).
    r"\.claude[/\\]settings(\.local)?\.json"
    r"|\.claude\.json"
    # Dotenv, including .envrc (direnv) — but NOT the non-secret templates.
    r"|\.envrc"
    r"|\.env(\.[\w.-]+)?"
    # Generic credential stores / token caches.
    r"|credentials[\w.-]*\.json"
    r"|application_default_credentials\.json"
    r"|access_tokens\.db|credentials\.db"
    # Private keys / keystores.
    r"|id_(rsa|ed25519|ecdsa|dsa)\w*"
    r"|[\w.-]+\.(pem|key|ppk|p12|pfx|jks)"
    # Cloud CLIs.
    r"|\.aws[/\\](credentials|config)"
    r"|\.azure[/\\][\w.-]+"
    r"|\.config[/\\]gcloud[/\\][\w.-]+"
    # Package / registry / infra.
    r"|\.npmrc|\.pypirc|\.netrc|_netrc"
    r"|\.docker[/\\]config\.json"
    r"|\.kube[/\\]config"
    r"|\.pgpass"
    r"|[\w.-]*\.tfstate|\.terraformrc|credentials\.tfrc\.json"
    r"|\.gnupg[/\\][\w.-]+"
    # Git / GitHub CLI plaintext credential stores.
    r"|\.git-credentials"
    r"|\.config[/\\]gh[/\\]hosts\.yml|GitHub CLI[/\\]hosts\.yml"
    # Shell history can contain a pasted secret; interactive rc/profile files
    # are deliberately NOT here (reading ~/.zshrc to debug PATH is routine, and
    # a secret exported there is caught at the env-var-read layer if printed).
    r"|\.(bash|zsh)_history"
    # Linux process environment — every secret env var, via a file path.
    r"|/proc/(self|\d+)/environ"
    r")\b",
    re.IGNORECASE,
)

# Dotenv templates that are safe to read — checked-in examples, never secret.
ENV_TEMPLATE = re.compile(
    r"\.env\.(example|sample|template|dist|defaults?)\b", re.IGNORECASE
)


# --- Environment dumps and targeted credential-var reads -------------------

ENV_DUMP_PATTERN = re.compile(
    r"^\s*env\s*$"                       # bare `env`
    r"|^\s*printenv\s*$"                 # bare `printenv`
    r"|^\s*set\s*$"                      # bare `set` (not `set -e` / `set -o`)
    r"|\bexport\s+-p\b"                  # `export -p`
    r"|\bdeclare\s+-\w*p\b"              # `declare -p` / `-px`
    r"|\bGet-ChildItem\b[^|]*\bEnv:"     # PowerShell env dump
    r"|\b(dir|ls|gci)\s+env:"
    r"|\bGet-Item\b[^|]*\bEnv:\*"
    r"|\bGet-Variable\b(?![^|]*-Name)"   # `Get-Variable` with no -Name = dump
    r"|\b(dir|ls)\s+variable:",
    re.IGNORECASE,
)

# A CLI subcommand that prints a registered server's stored env (incl. secrets)
# by design — pure command-shape, no file/path involved (the 07-03 addendum).
MCP_GET_PATTERN = re.compile(r"\bclaude\s+mcp\s+get\b", re.IGNORECASE)

# Credential-shaped environment variable names (the 07-02 founding shape).
_CRED_VAR = (
    r"\w*(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY"
    r"|SECRET_ACCESS_KEY|_KEY|_TOKEN|_SECRET|PASSWORD|PASSWD|_PAT"
    r"|ANTHROPIC_API_KEY|GITHUB_PERSONAL_ACCESS_TOKEN|GH_TOKEN|GITHUB_TOKEN"
    r"|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)\w*"
)
CRED_VAR_READ = re.compile(
    # printenv NAME
    r"\bprintenv\s+" + _CRED_VAR
    # echo/print $NAME, ${NAME}, $env:NAME
    + r"|(?:echo|printf|print|write-host|write-output)\b[^\n]*"
    + r"\$(?:\{)?(?:env:)?" + _CRED_VAR
    # [Environment]::GetEnvironmentVariable("NAME"...)
    + r"|GetEnvironmentVariable\(\s*['\"]?" + _CRED_VAR
    # a bare `$env:NAME` that stands alone (PowerShell echoes it)
    + r"|^\s*\$env:" + _CRED_VAR + r"\s*$",
    re.IGNORECASE,
)


# --- Bash/PowerShell command classification --------------------------------

# Leading commands that may name a sensitive path WITHOUT reading its content
# to stdout: existence/metadata checks, pure file management (delete/move/perm),
# navigation, string/echo, and version control. Everything else that names a
# sensitive path is treated as a read and blocked (default-deny).
SAFE_COMMANDS = {
    # existence / metadata
    "ls", "dir", "ll", "la", "vdir", "stat", "file", "test", "[", "[[",
    "du", "df", "wc", "readlink", "realpath", "basename", "dirname", "tree",
    # navigation / no-op / string
    "cd", "pushd", "popd", ":", "true", "false", "echo", "printf", "print",
    # file management (no file content to stdout)
    "rm", "unlink", "rmdir", "mkdir", "touch", "chmod", "chown", "chgrp",
    "truncate", "mv", "cp", "ln", "install", "mktemp", "shred",
    # version control (git never cats an arbitrary FS path to stdout; a commit
    # message quoting a sensitive path is the false positive v1's first draft
    # died on — keep it allowed)
    "git",
    # PowerShell metadata / file-management cmdlets
    "test-path", "get-item", "get-childitem", "resolve-path", "split-path",
    "remove-item", "new-item", "move-item", "copy-item", "rename-item",
    "get-location", "set-location", "get-acl",
}

# grep-family: a read (prints matched lines) UNLESS in an existence/count mode,
# which is exactly the safe alternative this guard recommends.
GREP_FAMILY = {"grep", "egrep", "fgrep", "rg", "ag", "ripgrep", "select-string"}
GREP_SAFE_FLAG = re.compile(
    r"(?<!\w)-{1,2}(l|L|c|q|files-with-matches|files-without-match"
    r"|count|quiet)\b"
)

# Prefixes that wrap a command without changing what it does.
_WRAPPERS = {"sudo", "command", "time", "nice", "nohup", "exec", "builtin",
             "\\", "then", "do", "else", "elif"}
_SUBSTITUTION = re.compile(r"\$\(|`|<\(")  # command / process substitution


def _leading_command(seg):
    """The first real command token in a segment, minus wrappers and VAR=val."""
    toks = seg.strip().lstrip("(").strip().split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in _WRAPPERS or re.match(r"^[A-Za-z_]\w*=", t):
            i += 1
            continue
        break
    if i >= len(toks):
        return ""
    return toks[i].split("/")[-1].split("\\")[-1].lower()


def _strip_heredocs(command):
    """Drop heredoc *bodies* so prose written into a file isn't scanned as
    commands (the `cat > notes <<EOF ... .env ... EOF` false-positive class).
    The line carrying the `<<` is kept — that one is a real command."""
    out, delim = [], None
    for line in command.split("\n"):
        if delim is None:
            out.append(line)
            m = re.search(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?", line)
            if m:
                delim = m.group(1)
        elif line.strip() == delim:
            delim = None
    return "\n".join(out)


def _reads_sensitive_path(seg):
    """True if the segment reads a sensitive target's content (default-deny)."""
    m = SENSITIVE_FILE_PATTERN.search(seg)
    if not m or ENV_TEMPLATE.search(seg):
        return False
    lead = _leading_command(seg)
    if lead in GREP_FAMILY:
        return not GREP_SAFE_FLAG.search(seg)          # content grep = read
    if lead in SAFE_COMMANDS:
        if lead == "find" and re.search(r"-exec(dir)?\b", seg):
            return True                                # find -exec <reader>
        return bool(_SUBSTITUTION.search(seg))         # echo $(cat secret) etc.
    return True                                        # unknown cmd → default deny


def block(message):
    """Write a block reason to stderr and exit with the hook's block code."""
    sys.stderr.write(message)
    sys.exit(2)


# --- Block messages --------------------------------------------------------

_MSG_PATH = (
    "CREDENTIAL GUARD (v2, path-based default-deny): this reads the content of a\n"
    "known credential-store target (Claude config / .env / SSH or other private\n"
    "keys / cloud, registry, or infra credential files / shell history /\n"
    "/proc/*/environ). Same exposure as `cat`-ing it, regardless of the reader\n"
    "used. To check existence without printing the value, use a metadata command\n"
    "(ls / stat / Test-Path) or grep in files_with_matches / count mode. If a full\n"
    "unmasked read is genuinely needed, re-invoke via Bash with MASK-OK in the\n"
    "command and having weighed the exposure.\n"
)
_MSG_ENV = (
    "CREDENTIAL GUARD: this dumps the environment (env / printenv / set /\n"
    "declare -p / Get-ChildItem Env:). Every credential-shaped var (*_TOKEN,\n"
    "*_KEY, *_SECRET) currently set gets printed in the clear. Check a specific\n"
    "non-secret var instead, e.g. `[bool]$env:VARNAME`. Re-invoke with MASK-OK\n"
    "if a full dump is genuinely needed and you've weighed the exposure.\n"
)
_MSG_VAR = (
    "CREDENTIAL GUARD: this prints a credential-shaped environment variable in\n"
    "the clear (this is the 2026-07-02 founding incident's exact shape). If you\n"
    "only need to know whether it's set, test `[bool]$env:NAME` or a\n"
    "truncated/masked read. Re-invoke with MASK-OK for a deliberate audit.\n"
)
_MSG_GREP = (
    "CREDENTIAL GUARD: content-mode Grep against a known credential-store file\n"
    "prints the full matched line — including the secret value next to the key.\n"
    "Use output_mode=files_with_matches or count instead, or Bash with MASK-OK\n"
    "if you genuinely need the value.\n"
)
_MSG_MCP = (
    "CREDENTIAL GUARD: `claude mcp get <name>` prints that server's stored env\n"
    "vars (including secrets) in the clear. Use `claude mcp list` to check\n"
    "connection status without revealing values, or Bash with MASK-OK if you\n"
    "genuinely need the stored value.\n"
)

# Every tool-input field that can carry a path to a content read. Checked on
# ALL tools (not a fixed {Read, Grep} pair), so a reader tool that isn't hooked
# yet is still covered — the structural fix for the 2026-07-04 tool-shape gap.
PATH_FIELDS = ("file_path", "path", "notebook_path", "filepath", "file", "uri")


def main():
    """PreToolUse hook: allow (exit 0) or block (exit 2) the tool call on stdin.

    Grep is checked for content-mode reads of sensitive paths; Bash/PowerShell
    commands are split into segments and checked for env dumps, credential-var
    prints, and sensitive-path reads (default-deny by leading command); Glob is
    allowed (it returns paths, not content); every other tool has all its
    path-bearing fields checked against the sensitive-target pattern. Fails open
    (exit 0) on an unparseable payload.
    """
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    # Grep: only content mode echoes the matched line. Check both the explicit
    # path and a glob that targets a sensitive file (path may be omitted).
    if tool_name == "Grep":
        if tool_input.get("output_mode") == "content":
            for field in ("path", "glob"):
                v = tool_input.get(field, "")
                if isinstance(v, str) and v and SENSITIVE_FILE_PATTERN.search(v) \
                        and not ENV_TEMPLATE.search(v):
                    block(_MSG_GREP)
        sys.exit(0)

    if tool_name in ("Bash", "PowerShell"):
        command = tool_input.get("command", "")
        if not command or "MASK-OK" in command:
            sys.exit(0)
        command = _strip_heredocs(command)
        for seg in re.split(r"\|\||&&|[;\n]|\|", command):
            seg = seg.strip()
            if not seg:
                continue
            if ENV_DUMP_PATTERN.search(seg):
                block(_MSG_ENV)
            if CRED_VAR_READ.search(seg):
                block(_MSG_VAR)
            if MCP_GET_PATTERN.search(seg):
                block(_MSG_MCP)
            if _reads_sensitive_path(seg):
                block(_MSG_PATH)
        sys.exit(0)

    # Glob returns paths, not content — it can confirm a file exists (the safe
    # fallback the guard itself recommends) but cannot print a secret's value.
    if tool_name == "Glob":
        sys.exit(0)

    # Every other tool (Read, NotebookEdit, MCP file readers, ...): block if any
    # path-bearing field targets a sensitive file. This is the default-deny that
    # closes the tool-shape gap by construction.
    for field in PATH_FIELDS:
        v = tool_input.get(field, "")
        if isinstance(v, str) and v and SENSITIVE_FILE_PATTERN.search(v) \
                and not ENV_TEMPLATE.search(v):
            block(_MSG_PATH)
    sys.exit(0)


if __name__ == "__main__":
    main()
