"""Command line: phi-guard, also available as python -m phi_guardrails."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, history, precommit, roster
from .errors import ConfigError, GuardError
from .scanner import Finding, Scanner, decode_text

ENV_ROSTER = "PHI_ROSTER_DIR"
ENV_DEBUG = "PHI_GUARD_DEBUG"
HOOK_COMMANDS = frozenset({"pre-commit", "commit-msg"})


def _roster_dir(args: argparse.Namespace) -> Path:
    value = args.roster_dir or os.environ.get(ENV_ROSTER)
    if not value:
        raise ConfigError(f"no roster folder; pass --roster-dir or set {ENV_ROSTER}")
    return Path(value)


def _scanner(args: argparse.Namespace) -> Scanner:
    if args.no_roster:
        print("WARN: running without a roster; only the pattern and secret checks apply.", file=sys.stderr)
        return Scanner(None)
    return Scanner(roster.load(_roster_dir(args)))


def cmd_init_key(args: argparse.Namespace) -> int:
    path = roster.init_key(_roster_dir(args) / roster.KEY_FILE)
    print(f"Created {path}. Keep it out of version control and back it up; a new key means a new roster.")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    counts = roster.build(args.sources, _roster_dir(args), staff_file=args.staff, merge=args.merge,
                          allow_empty=args.allow_empty)
    print(f"Roster built from {counts['files']} CSV files: {counts['pairs']} name pairs, "
          f"{counts['members']} member IDs, {counts['name_dob']} name+DOB entries.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    scanner = _scanner(args)
    findings = []
    for file in args.files:
        shown = scanner.display_path(str(file))
        if scanner.path_hit(str(file)):
            findings.append(Finding(shown, None, "roster.path"))
        try:
            data = Path(file).read_bytes()
        except OSError:
            raise ConfigError(f"cannot read {shown}") from None
        text = decode_text(data)
        if text is None:
            findings.append(Finding(shown, None, "binary.not_scanned"))
            continue
        findings += [Finding(shown, number, category) for number, category in scanner.check_text(text)]
    for finding in findings:
        print(finding)
    return 1 if findings else 0


def cmd_install_hooks(args: argparse.Namespace) -> int:
    for path in precommit.install_hooks(args.repo, roster_dir=args.roster_dir, force=args.force):
        print(f"Installed {path.name} hook.")
    if not args.roster_dir:
        print(f"Note: the hooks will read {ENV_ROSTER} at commit time.", file=sys.stderr)
    return 0


def cmd_pre_commit(args: argparse.Namespace) -> int:
    return _block(precommit.check_staged(Path.cwd(), _scanner(args)))


def cmd_commit_msg(args: argparse.Namespace) -> int:
    return _block(precommit.check_message(args.message_file, _scanner(args)))


def _block(findings: list[Finding]) -> int:
    for finding in findings:
        print(f"BLOCKED {finding}")
    if not findings:
        return 0
    noun = "finding" if len(findings) == 1 else "findings"
    print(f"phi-guardrails stopped this commit ({len(findings)} {noun}). Remove the data, or end a line that is "
          "a reviewed false positive with '# phi-ok: <reason>'.", file=sys.stderr)
    return 1


def cmd_scan_history(args: argparse.Namespace) -> int:
    probe = subprocess.run(["git", "-C", str(args.repo), "rev-parse", "--git-dir"], capture_output=True)
    if probe.returncode != 0:
        raise ConfigError("not a git repository")
    report = history.scan_history(args.repo, _scanner(args))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(history.format_summary(report))
    return 0 if history.is_clean(report) else 1


def build_parser() -> argparse.ArgumentParser:
    roster_opt = argparse.ArgumentParser(add_help=False)
    roster_opt.add_argument("--roster-dir", type=Path, metavar="DIR",
                            help=f"folder holding {roster.KEY_FILE} and {roster.ROSTER_FILE} "
                                 f"(default: ${ENV_ROSTER}); keep it outside every repository")
    scan_opt = argparse.ArgumentParser(add_help=False)
    scan_opt.add_argument("--no-roster", action="store_true",
                          help="skip the roster and run only the pattern and secret checks")

    parser = argparse.ArgumentParser(
        prog="phi-guard",
        description="Keep patient identifiers out of git history. Output names a path, a line and a category, "
                    "never the matched text.",
        epilog="Exit codes: 0 clean, 1 findings, files needing review, or commit blocked, "
               "2 usage or setup error.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("init-key", parents=[roster_opt], help="create the roster key (never overwrites one)",
                       description="Create a random 32-byte roster key. Refuses to replace an existing key.")
    p.set_defaults(func=cmd_init_key)

    p = sub.add_parser("build", parents=[roster_opt], help="build the roster from patient CSV exports",
                       description="Hash the names, member IDs and birth dates in CSV exports into the roster.")
    p.add_argument("sources", nargs="+", type=Path, metavar="CSV", help="CSV files, or folders of CSV files")
    p.add_argument("--staff", type=Path, metavar="FILE", help="staff names to leave out, one per line")
    p.add_argument("--merge", action="store_true",
                   help="also keep everything already in the roster, so a deleted export never drops patients")
    p.add_argument("--allow-empty", action="store_true",
                   help="skip CSV files with no recognizable name columns instead of stopping")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("check", parents=[roster_opt, scan_opt], help="check files on disk",
                       description="Check whole files. Lines marked '# phi-ok: <reason>' are skipped.")
    p.add_argument("files", nargs="+", type=Path, metavar="FILE")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("install-hooks", parents=[roster_opt],
                       help="install the pre-commit, pre-merge-commit and commit-msg hooks",
                       description="Write git hooks that run phi-guardrails with this Python interpreter.")
    p.add_argument("--repo", type=Path, default=Path("."), help="repository to install into (default: .)")
    p.add_argument("--force", action="store_true", help="replace hooks that phi-guardrails did not write")
    p.set_defaults(func=cmd_install_hooks)

    p = sub.add_parser("pre-commit", parents=[roster_opt, scan_opt], help="git hook: check staged changes",
                       description="Check the lines a commit adds and block binaries that are not allowlisted "
                                   f"in {precommit.ALLOW_FILE}.")
    p.set_defaults(func=cmd_pre_commit)

    p = sub.add_parser("commit-msg", parents=[roster_opt, scan_opt], help="git hook: check the commit message",
                       description="Check a commit message file.")
    p.add_argument("message_file", type=Path, metavar="FILE")
    p.set_defaults(func=cmd_commit_msg)

    p = sub.add_parser("scan-history", parents=[roster_opt, scan_opt],
                       help="scan every file version, commit message and tag message in a repository",
                       description="Scan every blob reachable from any ref, every commit and tag message, and "
                                   "every ref name. Files that can't be read and aren't in .phi-binary-allow "
                                   "make the result 'needs review'. Run it before a repository goes public.")
    p.add_argument("repo", nargs="?", type=Path, default=Path("."), help="repository to scan (default: .)")
    p.add_argument("--json", type=Path, metavar="OUT",
                   help="also write the full report here (masked paths and categories only); "
                        "keep it outside the repository")
    p.set_defaults(func=cmd_scan_history)
    return parser


def _tolerant_output() -> None:
    """Escape characters the console can't encode instead of crashing on them.

    On Windows, piped output (GUI git clients, > out.txt) is often cp1252, and a
    path like docs/日本.md would otherwise raise UnicodeEncodeError mid-report.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _tolerant_output()
    args = build_parser().parse_args(argv)
    hook = args.command in HOOK_COMMANDS
    try:
        return args.func(args)
    except GuardError as exc:
        print(f"{'BLOCKED' if hook else 'phi-guard'}: {exc}", file=sys.stderr)
        return 1 if hook else 2
    except Exception:
        if os.environ.get(ENV_DEBUG) == "1":
            raise
        # Exception text can quote file contents, so only a fixed message is printed.
        if hook:
            print("BLOCKED: phi-guardrails hit an unexpected error, so the commit was stopped. "
                  f"Set {ENV_DEBUG}=1 to see the traceback (it may include file contents).", file=sys.stderr)
            return 1
        print(f"phi-guard: unexpected error. Set {ENV_DEBUG}=1 to see the traceback "
              "(it may include file contents).", file=sys.stderr)
        return 2
