"""Git hooks: check what is about to be committed.

pre-commit looks at the lines a commit adds, not whole files. A repository with
old problems can still take new commits; scan-history is the tool for finding
what is already there.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

from .errors import ConfigError
from .scanner import Finding, Scanner, decode_as, decode_text, text_lines, wide_encoding

ALLOW_FILE = ".phi-binary-allow"
HOOK_MARK = "# installed by phi-guardrails"
HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)
SUBMODULE = b"160000"
# Formats a text scanner can't read. Spreadsheets, PDFs and screenshots are
# where patient data usually hides, so they need an explicit allowlist entry.
BINARY_EXT = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic",
    ".pdf", ".xlsx", ".xlsm", ".xls", ".docx", ".doc", ".pptx", ".ppt",
    ".zip", ".7z", ".gz", ".tar", ".db", ".sqlite", ".sqlite3", ".parquet", ".pkl", ".pickle",
})
# git's cut line for "commit -v" and the scissors cleanup mode: git drops everything below it.
SCISSORS = "------------------------ >8 ------------------------"
# What git's editor template says, word for word, when it will cut at that line,
# drop comment lines, or keep them. See message_lines.
CUT_HINT = "Do not modify or remove the line above."
HINT_START = "Please enter the commit message for your changes. Lines starting"
STRIP_HINT = "with '{}' will be ignored, and an empty message aborts the commit."
KEEP_HINT = "with '{}' will be kept; you may remove them yourself if you want to."
# Objects as stored. "git replace" can swap in a clean stand-in for any object, and a
# check that followed replacements would read the stand-in instead of what gets pushed.
GIT = ("git", "--no-replace-objects")
# Characters core.commentChar=auto may pick.
AUTO_COMMENT_CHARS = tuple("#;@!$%^&|:")
# The hook runs this instead of "python -m", which would put the repository
# folder first on sys.path and let a repo's own json.py or csv.py shadow the stdlib.
# An empty PYTHONPATH entry also means the repository, spelled as an absolute path.
# Those entries move to the end rather than going away, so the package still loads
# when the hooks guard this repository itself.
RUNNER = ('import os, sys; here = os.path.realpath(os.getcwd()); '
          'local = [p for p in sys.path if os.path.realpath(p or ".") == here]; '
          'sys.path[:] = [p for p in sys.path if p not in local] + local; '
          'from phi_guardrails.cli import main; sys.exit(main())')


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, check=True).stdout


def _config(repo: Path, name: str) -> str:
    try:
        return _git(repo, "config", "--get", name).decode("utf-8", "replace").rstrip("\r\n")
    except subprocess.CalledProcessError:
        return ""


def staged_files(repo: Path) -> list[tuple[str, str]]:
    """(path, blob id) for each added, copied, modified or type-changed file in the index."""
    names = _git(repo, "diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACMT")
    wanted = {name for name in names.split(b"\0") if name}
    index = {}
    for entry in _git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        meta, _, path = entry.partition(b"\t")
        if path in wanted:
            mode, blob, _stage = meta.split(b" ")
            index[path] = (mode, blob)
    return [(path.decode("utf-8", "surrogateescape"), index[path][1].decode("ascii"))
            for path in sorted(wanted) if index[path][0] != SUBMODULE]


def added_lines(repo: Path, path: str) -> list[int]:
    """Line numbers, in the staged version of path, of lines this commit adds."""
    diff = _git(repo, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
                "--no-renames", "--text", "--", f":(literal){path}")
    lines = []
    for match in HUNK.finditer(diff):
        start = int(match.group(1))
        count = 1 if match.group(2) is None else int(match.group(2))
        lines.extend(range(start, start + count))
    return lines


def binary_allowlist(repo: Path, treeish: str = "") -> list[str]:
    """Globs from .phi-binary-allow, read from the index by default so the allowlist is reviewed like code.

    treeish="HEAD" reads the committed copy instead, which is what scan-history uses.
    """
    try:
        data = _git(repo, "cat-file", "blob", f"{treeish}:{ALLOW_FILE}")
    except subprocess.CalledProcessError:
        return []
    entries = (line.strip() for line in data.decode("utf-8", "replace").splitlines())
    return [entry for entry in entries if entry and not entry.startswith("#")]


def allowlisted(paths: list[str], allowed: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for path in paths for pattern in allowed)


def check_staged(repo: Path, scanner: Scanner) -> list[Finding]:
    findings = []
    allowed = binary_allowlist(repo)
    for path, blob in staged_files(repo):
        shown = scanner.display_path(path)
        if scanner.path_hit(path):
            findings.append(Finding(shown, None, "roster.path"))
        data = _git(repo, "cat-file", "blob", blob)
        text = None if PurePosixPath(path).suffix.lower() in BINARY_EXT else decode_text(data)
        if text is None:
            if not allowlisted([path], allowed):
                findings.append(Finding(shown, None, "binary.not_allowlisted"))
            continue
        lines = text_lines(text)
        # git's line numbers for UTF-16 and UTF-32 files don't always match the
        # decoded text, so those files are checked in full.
        numbers = range(1, len(lines) + 1) if wide_encoding(data) else added_lines(repo, path)
        for number in numbers:
            if 0 < number <= len(lines):
                findings.extend(Finding(shown, number, c) for c in scanner.check_line(lines[number - 1]))
    return findings


def comment_prefixes(repo: Path) -> tuple[str, ...]:
    """The comment marker git uses in this repository's commit messages."""
    for name in ("core.commentString", "core.commentChar"):
        value = _config(repo, name)
        if value:
            return AUTO_COMMENT_CHARS if value == "auto" else (value,)
    return ("#",)


def message_lines(text: str, prefixes: tuple[str, ...], editor: bool = True) -> list[str]:
    """The commit message as git will store it, for the parts that matter here.

    git runs commit-msg before it cleans up the message, and hooks can't see
    the --cleanup option. The editor template says what git will do, though.
    It opens its comment block with a two-line hint saying comment lines
    "will be ignored" or "will be kept", then lists the files in the commit
    ("#<TAB>deleted:    exports/<name>.csv"). Checking that list would block
    the very commit that removes a patient file, so after a "will be ignored"
    hint its lines are blanked (keeping line numbers right). Other comment
    lines are checked. When git is about to cut at the scissors line, it
    writes "Do not modify or remove the line above" under that line, and the
    check stops at the cut. The scissors mode writes no hint and cuts at the
    first such line; "commit -v" puts its cut line below the hint, and only
    a cut line there counts, because without -v git cuts nowhere.

    After a "will be kept" hint (--cleanup=verbatim or whitespace) nothing is
    skipped: git keeps the file list, and cuts only if -v was given, which a
    hook can't tell. Without an editor (-m, -F) git runs the hook with
    GIT_EDITOR=: and keeps every line, so every line is checked. So is a
    message from a git that writes its template in another language.
    """
    lines = text_lines(text)
    if not editor or any(_after_hint(lines, prefix, KEEP_HINT) is not None for prefix in prefixes):
        return lines
    strip, start = next(((prefix, start) for prefix in prefixes
                         if (start := _after_hint(lines, prefix, STRIP_HINT)) is not None), (None, 0))
    # A cut line saved with CRLF is no cut to Linux git (2.53 keeps the diff below it in the
    # commit), though Git for Windows cuts there. Only a bare-LF cut line counts.
    cuts = [number for number, line in enumerate(text.split("\n"))
            if number >= start and any(line == f"{prefix} {SCISSORS}" for prefix in prefixes)]
    if any(lines[number + 1:number + 2] == [f"{prefix} {CUT_HINT}"] for number in cuts for prefix in prefixes):
        lines = lines[:cuts[0]]
    if strip is None:
        return lines
    return lines[:start] + ["" if line.startswith(f"{strip}\t") else line for line in lines[start:]]


def _after_hint(lines: list[str], prefix: str, second: str) -> int | None:
    """Where the lines after git's two-line template hint start, or None when the hint isn't there."""
    hint = [f"{prefix} {HINT_START}", f"{prefix} {second.format(prefix)}"]
    return next((number + 2 for number in range(len(lines) - 1) if lines[number:number + 2] == hint), None)


def message_text(data: bytes, repo: Path) -> str | None:
    """A commit message as text, or None when it can't be read reliably.

    i18n.commitEncoding names the encoding when it is set. Otherwise the
    message is UTF-8 or, from older Windows tools, Windows-1252. Decoding with
    replacement characters instead would turn an accented name into one the
    roster doesn't know.
    """
    encoding = _config(repo, "i18n.commitEncoding")
    text = decode_as(data, encoding) if encoding else None
    return text if text is not None else decode_text(data, lenient=True)


def check_message(message_file: Path, scanner: Scanner, repo: Path | None = None) -> list[Finding]:
    repo = repo or Path.cwd()
    text = message_text(Path(message_file).read_bytes(), repo)
    if text is None:
        return [Finding("commit message", None, "message.unreadable")]
    lines = message_lines(text, comment_prefixes(repo), editor=os.environ.get("GIT_EDITOR") != ":")
    return [Finding("commit message", number, c)
            for number, line in enumerate(lines, 1) for c in scanner.check_line(line)]


def install_hooks(repo: Path, *, roster_dir: Path | None = None, force: bool = False) -> list[Path]:
    """Write pre-commit, pre-merge-commit and commit-msg hooks that run this package with this interpreter."""
    repo = Path(repo)
    hooks = Path(_git(repo, "rev-parse", "--git-path", "hooks").decode().strip())
    if not hooks.is_absolute():
        hooks = repo / hooks
    run = f"exec {shlex.quote(Path(sys.executable).as_posix())} -c {shlex.quote(RUNNER)}"
    extra = f" --roster-dir {shlex.quote(Path(roster_dir).resolve().as_posix())}" if roster_dir else ""
    scripts = {
        "pre-commit": f"{run} pre-commit{extra}",
        # A merge commit skips pre-commit; this hook sees the merged index the same way.
        "pre-merge-commit": f"{run} pre-commit{extra}",
        "commit-msg": f'{run} commit-msg{extra} "$1"',
    }
    for name in scripts:
        target = hooks / name
        if target.exists() and not force and HOOK_MARK not in target.read_text(encoding="utf-8", errors="replace"):
            raise ConfigError(f"a {name} hook already exists; rerun with --force to replace it")
    hooks.mkdir(parents=True, exist_ok=True)
    written = []
    for name, command in scripts.items():
        target = hooks / name
        target.write_text(f"#!/bin/sh\n{HOOK_MARK}\n{command}\n", encoding="utf-8", newline="\n")
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(target)
    return written
