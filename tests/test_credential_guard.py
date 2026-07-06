#!/usr/bin/env python3
"""Adversarial test suite for security/credential-guard.py.

One case (or more) per bypass shape in the ADR-003 taxonomy, plus the
false-positive / allow cases that keep the guard usable — a guard that blocks
routine work (a commit message quoting an example, `grep -l`, reading a
`.env.example`) gets routed around, which is as much a failure as a missed
leak. This is the mechanical version of the decoy-file smoke test in
security/README.md: every extension to the guard has to be exercised against a
real blocked case AND a real allowed case before it's trusted.

Stdlib only (no pytest, no third-party deps) so CI is a bare `python -m
unittest`. The guard is driven exactly as the harness drives it: a PreToolUse
JSON payload on stdin, exit 0 = allow, exit 2 = block. No real secret values
appear anywhere here — the guard keys on paths and command shapes, so the test
inputs reference sensitive *paths* and fake variable *names*, never a token.

Shapes deliberately NOT blocked (bounded out by the non-adversarial threat
model — see the guard docstring and posture.md) are asserted as ALLOWED so the
boundary is explicit and a future well-meaning "fix" that blocks them fails a
test on purpose: copy-launder (8), script indirection via `bash x.sh` (11),
and MASK-OK override (15).
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent / "security" / "credential-guard.py"

ALLOW = 0
BLOCK = 2


def run_guard(tool_name, tool_input):
    """Invoke the guard with a PreToolUse payload; return its exit code."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=payload,
        capture_output=True,
        text=True,
    )
    return proc.returncode


class GuardTestCase(unittest.TestCase):
    def assertBlocked(self, tool_name, tool_input, msg=""):
        self.assertEqual(run_guard(tool_name, tool_input), BLOCK,
                         f"expected BLOCK: {msg or tool_input}")

    def assertAllowed(self, tool_name, tool_input, msg=""):
        self.assertEqual(run_guard(tool_name, tool_input), ALLOW,
                         f"expected ALLOW: {msg or tool_input}")

    def bash(self, command):
        return ("Bash", {"command": command})

    def ps(self, command):
        return ("PowerShell", {"command": command})


class TestHistoricalShapes(GuardTestCase):
    """Shapes 1-7: each maps to one of the four 2026-07 incidents."""

    def test_shape1_single_env_var_read(self):
        # 2026-07-02 founding incident — v1 never caught this.
        self.assertBlocked(*self.bash("printenv ANTHROPIC_API_KEY"))
        self.assertBlocked(*self.bash("echo $ANTHROPIC_API_KEY"))
        self.assertBlocked(*self.ps(
            '[Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY", "User")'))

    def test_shape2_bulk_env_dump(self):
        self.assertBlocked(*self.bash("printenv"))
        self.assertBlocked(*self.bash("env"))
        # dump-then-filter: v1's `\s*$` anchor + no `|` split let this through.
        self.assertBlocked(*self.bash("env | grep -i token"))

    def test_shape3_shell_cat_read(self):
        self.assertBlocked(*self.bash("cat ~/.claude/settings.json"))

    def test_shape4_interpreter_read(self):
        self.assertBlocked(*self.bash(
            "python3 -c \"print(open('/home/user/.claude.json').read())\""))
        self.assertBlocked(*self.ps(
            '[System.IO.File]::ReadAllText("$HOME/.claude.json")'))

    def test_shape5_read_tool(self):
        self.assertBlocked("Read", {"file_path": "/home/user/.claude.json"})

    def test_shape6_grep_content(self):
        self.assertBlocked("Grep", {"path": "/home/user/.claude.json",
                                    "pattern": "TOKEN", "output_mode": "content"})

    def test_shape7_mcp_get(self):
        # `claude mcp get` prints stored env vars by design.
        self.assertBlocked(*self.bash("claude mcp get github"))


class TestLatentShapes(GuardTestCase):
    """Shapes 8-18: latent/adversarial — several were live gaps in v1."""

    def test_shape9_alt_readers(self):
        # The biggest v1 hole: any pager/dumper/formatter that isn't `cat`.
        for cmd in [
            "head ~/.claude.json",
            "tail -n5 ~/.claude.json",
            "base64 /home/user/.env",
            "xxd ~/.ssh/id_rsa",
            "strings ~/.aws/credentials",
            "jq . /home/user/.claude.json",
            "awk '{print}' /home/user/.env",
            "od -c ~/.ssh/id_ed25519",
        ]:
            self.assertBlocked(*self.bash(cmd), msg=cmd)

    def test_shape10_redirection_read(self):
        self.assertBlocked(*self.bash("read TOKEN < /home/user/.env"))
        self.assertBlocked(*self.bash("cat < ~/.claude.json"))

    def test_shape12_proc_environ(self):
        self.assertBlocked(*self.bash("cat /proc/self/environ"))
        self.assertBlocked(*self.bash("tr '\\0' '\\n' < /proc/self/environ"))

    def test_shape13_builtin_var_dump(self):
        self.assertBlocked(*self.bash("declare -p"))
        self.assertBlocked(*self.bash("export -p"))
        self.assertBlocked(*self.bash("set"))

    def test_shape14_uncovered_paths_now_covered(self):
        for path in [
            "/home/user/.git-credentials",
            "/home/user/.envrc",
            "/home/user/.ssh/id_ecdsa",
            "/home/user/.pypirc",
            "/home/user/terraform.tfstate",
            "/home/user/.config/gcloud/credentials.db",
        ]:
            self.assertBlocked("Read", {"file_path": path}, msg=path)

    def test_shape16_unhooked_tool(self):
        # The 07-04 lesson, one tool-generation on: a content tool the hook
        # never names must still be covered via its path field.
        self.assertBlocked("mcp__filesystem__read_file",
                           {"path": "/home/user/.claude.json"})
        self.assertBlocked("NotebookRead",
                           {"notebook_path": "/home/user/.env"})

    def test_shape18_grep_glob_omitted_path(self):
        # content Grep with path omitted but a glob that targets .env
        self.assertBlocked("Grep", {"pattern": "SECRET", "output_mode": "content",
                                    "glob": "**/.env"})


class TestBoundedOutOfScope(GuardTestCase):
    """Shapes explicitly NOT blocked — the permission layer + rotation own
    these. Asserted as ALLOWED so the boundary is a test, not an assumption."""

    def test_shape8_copy_launder_allowed(self):
        # `cp` is safe (not a read); the copy's content-read hits a non-sensitive
        # path. Bounded by the permission layer, documented in the guard.
        self.assertAllowed(*self.bash("cp /home/user/.claude.json /tmp/x"))

    def test_shape11_script_indirection_allowed(self):
        self.assertAllowed(*self.bash("bash leak.sh"))

    def test_shape15_mask_ok_override(self):
        self.assertAllowed(*self.bash("cat ~/.claude.json  # MASK-OK"))

    def test_shape11_source_is_still_blocked(self):
        # `source .env` is NOT indirection-through-a-file — it names the path
        # and `source` isn't a safe verb, so default-deny catches it.
        self.assertBlocked(*self.bash("source /home/user/.env"))

    def test_shape17_wildcard_path_assembly_allowed(self):
        # A path-regex can't resolve `~/.claud*.json` without also matching
        # innocent globs like `~/.config*.json`. Bounded by the permission
        # layer + rotation, same as copy-launder. Documented in the guard.
        self.assertAllowed(*self.bash("cat ~/.claud*.json"))


class TestFalsePositives(GuardTestCase):
    """The discipline that killed v1's first over-broad draft: routine work
    that merely NAMES a sensitive path, or checks its existence, must pass."""

    def test_commit_message_quoting_example(self):
        # v1's first draft blocked its own commit message for this.
        self.assertAllowed(*self.bash(
            'git commit -m "fix the cat ~/.claude.json leak in the guard"'))
        self.assertAllowed(*self.bash('git add .env.example && git status'))

    def test_echo_and_prose_mentioning_path(self):
        self.assertAllowed(*self.bash('echo "remember to edit your .env file"'))

    def test_heredoc_body_is_prose(self):
        self.assertAllowed(*self.bash(
            "cat > notes.md <<'EOF'\nSet the token in ~/.claude.json\nEOF"))

    def test_existence_and_metadata_checks(self):
        for cmd in [
            "ls -la ~/.ssh/",
            "stat /home/user/.claude.json",
            "test -f /home/user/.env && echo present",
            "rm /home/user/.env.bak",
            "grep -l TOKEN /home/user/.env",
        ]:
            self.assertAllowed(*self.bash(cmd), msg=cmd)

    def test_powershell_existence_check(self):
        self.assertAllowed(*self.ps("Test-Path $HOME/.claude.json"))

    def test_env_template_files_allowed(self):
        self.assertAllowed("Read", {"file_path": "/home/user/.env.example"})
        self.assertAllowed(*self.bash("cat /home/user/.env.sample"))

    def test_safe_grep_modes_allowed(self):
        self.assertAllowed("Grep", {"path": "/home/user/.claude.json",
                                    "pattern": "TOKEN",
                                    "output_mode": "files_with_matches"})
        self.assertAllowed("Grep", {"path": "/home/user/.claude.json",
                                    "pattern": "TOKEN", "output_mode": "count"})

    def test_glob_returns_paths_not_content(self):
        self.assertAllowed("Glob", {"pattern": "**/.env"})

    def test_setting_a_var_is_not_reading_it(self):
        # `set -e` / `set -o` must not trip the bare-`set` dump rule.
        self.assertAllowed(*self.bash("set -euo pipefail"))
        self.assertAllowed(*self.bash("export API_BASE=https://example.com"))

    def test_reading_non_sensitive_file_allowed(self):
        self.assertAllowed("Read", {"file_path": "/home/user/project/main.py"})
        self.assertAllowed(*self.bash("cat README.md"))

    def test_malformed_payload_fails_open(self):
        proc = subprocess.run([sys.executable, str(GUARD)],
                              input="not json", capture_output=True, text=True)
        self.assertEqual(proc.returncode, ALLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
