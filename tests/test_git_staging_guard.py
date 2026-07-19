#!/usr/bin/env python3
"""Test suite for hooks/git-staging-guard.py.

Two halves, and the second is the one that decides whether the guard survives:
the blocked shapes (whole-tree staging) and the allowed ones that keep it
usable. `credential-guard`'s v1 blocked its own commit message for quoting an
example, and this guard is *more* exposed to that failure — the incidents it
exists to prevent are described in commit messages and PR bodies that quote
`git add -u` verbatim. A guard that cannot document itself gets routed around,
which is a worse outcome than the mistake it prevents.

So the prose cases below are not padding. They are the reason the guard strips
heredoc bodies and tokenizes with `shlex` instead of grepping for a flag.

Stdlib only (no pytest) so CI is a bare `python -m unittest`. The guard is
driven exactly as the harness drives it: a PreToolUse JSON payload on stdin,
exit 0 = allow, exit 2 = block.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent / "hooks" / "git-staging-guard.py"


def run(command: str, tool_name: str = "Bash") -> int:
    """Drive the guard the way the harness does; return its exit code."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, str(GUARD)], input=payload, capture_output=True, text=True
    )
    return proc.returncode


BLOCK, ALLOW = 2, 0


class TestWholeTreeStagingBlocked(unittest.TestCase):
    """The shapes that caused real incidents."""

    def test_add_all_short(self) -> None:
        self.assertEqual(run("git add -A"), BLOCK)

    def test_add_update_short(self) -> None:
        self.assertEqual(run("git add -u"), BLOCK)

    def test_add_dot(self) -> None:
        self.assertEqual(run("git add ."), BLOCK)

    def test_add_long_forms(self) -> None:
        self.assertEqual(run("git add --all"), BLOCK)
        self.assertEqual(run("git add --update"), BLOCK)

    def test_add_with_dash_c_repo_flag(self) -> None:
        """`git -C <repo> add -u` is the shape the house style actually uses."""
        self.assertEqual(run("git -C /some/repo add -u"), BLOCK)

    def test_commit_all(self) -> None:
        self.assertEqual(run("git commit -a -m 'x'"), BLOCK)
        self.assertEqual(run("git commit --all -m 'x'"), BLOCK)

    def test_commit_combined_short_flags(self) -> None:
        self.assertEqual(run("git commit -am 'x'"), BLOCK)

    def test_later_segment_of_a_compound_command(self) -> None:
        """The offence is rarely first: `add && commit && push` is the real shape."""
        self.assertEqual(run("git status && git add -A"), BLOCK)
        self.assertEqual(run("git add -u && git commit -m 'x' && git push"), BLOCK)

    def test_pathspec_does_not_rescue_dash_a(self) -> None:
        """`-A -- src/` still stages every tracked change under that path."""
        self.assertEqual(run("git add -A -- src/"), BLOCK)


class TestCorrectHabitAllowed(unittest.TestCase):
    """Explicit paths — the behaviour the guard is steering toward."""

    def test_explicit_paths(self) -> None:
        self.assertEqual(run("git add src/api.py tests/test_api.py"), ALLOW)

    def test_explicit_path_with_dash_c(self) -> None:
        self.assertEqual(run("git -C /some/repo add docs/README.md"), ALLOW)

    def test_explicit_after_double_dash(self) -> None:
        self.assertEqual(run("git add -- src/api.py"), ALLOW)

    def test_ordinary_commit(self) -> None:
        self.assertEqual(run("git commit -m 'x'"), ALLOW)

    def test_amend_is_not_dash_a(self) -> None:
        """`--amend` contains 'a' but is long-form; a sloppy matcher blocks it."""
        self.assertEqual(run("git commit --amend --no-edit"), ALLOW)

    def test_patch_mode(self) -> None:
        self.assertEqual(run("git add -p"), ALLOW)

    def test_unrelated_git_subcommands(self) -> None:
        self.assertEqual(run("git status --porcelain"), ALLOW)
        self.assertEqual(run("git stash -u"), ALLOW)
        self.assertEqual(run("git clean -A"), ALLOW)

    def test_not_git_at_all(self) -> None:
        self.assertEqual(run("npm add -A"), ALLOW)

    def test_non_shell_tools_are_ignored(self) -> None:
        self.assertEqual(run("git add -A", tool_name="Read"), ALLOW)


class TestProseIsNotACommand(unittest.TestCase):
    """The guard must be able to document its own incidents.

    Every case here appears, in substance, in the commit messages and PR bodies
    written the day this guard was built. If the guard blocks them it cannot
    explain itself, and it will be disabled rather than obeyed.
    """

    def test_flag_inside_a_commit_message(self) -> None:
        self.assertEqual(run("git commit -m 'fixed a git add -u sweep'"), ALLOW)

    def test_flag_inside_echo(self) -> None:
        self.assertEqual(run("echo 'never use git add -A'"), ALLOW)

    def test_flag_inside_a_heredoc_body(self) -> None:
        command = (
            "git commit -F - <<'EOF'\n"
            "docs: explain the incident\n\n"
            "A `git add -u` swept six files into this commit.\n"
            "EOF"
        )
        self.assertEqual(run(command), ALLOW)

    def test_flag_inside_a_pr_body_heredoc(self) -> None:
        command = (
            "gh pr create --body \"$(cat <<'EOF'\n"
            "We stopped using git add -A here.\n"
            "EOF\n"
            ')"'
        )
        self.assertEqual(run(command), ALLOW)


class TestOverride(unittest.TestCase):
    """A per-command opt-in, deliberately not a setting."""

    def test_override_prefix(self) -> None:
        self.assertEqual(run("STAGE-ALL-OK git add -A"), ALLOW)


class TestFailOpen(unittest.TestCase):
    """A hook that crashes must not wedge every tool call."""

    def test_unparseable_payload_allows(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(GUARD)], input="not json", capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, ALLOW)

    def test_missing_command_allows(self) -> None:
        payload = json.dumps({"tool_name": "Bash", "tool_input": {}})
        proc = subprocess.run(
            [sys.executable, str(GUARD)], input=payload, capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, ALLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
