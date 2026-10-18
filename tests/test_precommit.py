"""pre-commit and commit-msg hooks, run against real temporary git repositories."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fakes import PATIENTS, PROJECT_ROOT, assert_no_values, commit, git, stage

from phi_guardrails import cli, precommit, roster


def run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


@pytest.fixture
def hook(repo, roster_dir, monkeypatch, capsys):
    """Run the pre-commit command inside the test repository, as git would."""
    monkeypatch.chdir(repo)
    return lambda *extra: run(["pre-commit", "--roster-dir", str(roster_dir), *extra], capsys)


def test_blocks_a_staged_patient_name(repo, hook):
    p = PATIENTS[0]
    stage(repo, {"scripts/retry.py": f'print("retrying claim")\nPATIENT = "{p.full_name}"  # temporary\n'})
    code, output = hook()
    assert code == 1
    assert "BLOCKED scripts/retry.py:2 roster.name_pair" in output
    assert_no_values(output)


def test_reports_every_category_on_a_line(repo, hook):
    p = PATIENTS[1]
    stage(repo, {"fixtures.json": f'{{"name": "{p.full_name}", "dob": "{p.dob}", "id": "{p.member_id}"}}\n'})
    code, output = hook()
    assert code == 1
    for category in ("roster.name_pair", "roster.member_id", "roster.name_dob", "pattern.dob_field"):
        assert f"fixtures.json:1 {category}" in output
    assert_no_values(output)


def test_clean_change_passes(repo, hook):
    stage(repo, {"scripts/retry.py": "for claim in queue:\n    retry(claim)\n"})
    assert hook() == (0, "")


def test_only_added_lines_are_checked(repo, hook):
    p = PATIENTS[2]
    commit(repo, {"legacy.py": f"OLD = '{p.full_name}'\nA = 1\nB = 2\n"}, "legacy file")
    stage(repo, {"legacy.py": f"OLD = '{p.full_name}'\nA = 1\nB = 3\n"})
    assert hook() == (0, "")


def test_phi_ok_needs_a_reason(repo, hook):
    p = PATIENTS[3]
    stage(repo, {
        "with_reason.py": f'DEMO = "{p.full_name}"  # phi-ok: synthetic name used in the docs\n',
        "no_reason.py": f'DEMO = "{p.full_name}"  # phi-ok:\n',
    })
    code, output = hook()
    assert code == 1
    assert "no_reason.py:1 roster.name_pair" in output
    assert "with_reason.py" not in output


def test_binaries_need_an_allowlist_entry(repo, hook):
    stage(repo, {"docs/chart.png": b"\x89PNG\r\n\x1a\n" + bytes(16), "exports/aging.xlsx": b"PK\x03\x04" + bytes(12)})
    code, output = hook()
    assert code == 1
    assert "BLOCKED docs/chart.png binary.not_allowlisted" in output
    assert "BLOCKED exports/aging.xlsx binary.not_allowlisted" in output

    stage(repo, {".phi-binary-allow": "# reviewed by hand\ndocs/*.png\n"})
    code, output = hook()
    assert code == 1
    assert "docs/chart.png" not in output
    assert "exports/aging.xlsx binary.not_allowlisted" in output


def test_text_that_is_not_utf8_counts_as_binary(repo, hook):
    stage(repo, {"notes.txt": "café visit\n".encode("cp1252")})
    code, output = hook()
    assert code == 1 and "notes.txt binary.not_allowlisted" in output


def test_utf16_text_is_read_not_blocked_as_binary(repo, hook):
    # Windows PowerShell 5.1 writes UTF-16 with a byte-order mark by default.
    p = PATIENTS[2]
    stage(repo, {"export.txt": f"visit list\r\n{p.full_name}\r\n".encode("utf-16")})
    code, output = hook()
    assert code == 1
    assert "export.txt:2 roster.name_pair" in output and "binary" not in output
    assert_no_values(output)


def test_a_path_that_names_a_patient_is_masked(repo, hook):
    p = PATIENTS[4]
    path = f"exports/{p.last}_{p.first}.csv"
    stage(repo, {path: "visit_count\n3\n"})
    code, output = hook()
    assert code == 1
    assert "<masked:" in output and "roster.path" in output
    # The mask is keyed: a plain hash of the path could be reversed by guessing names.
    assert hashlib.sha256(path.encode()).hexdigest()[:12] not in output
    assert_no_values(output)
    assert p.first not in output


def test_no_roster_mode_still_catches_secrets(repo, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    stage(repo, {"settings.py": "TOKEN = '" + "gh" + "p_" + "Zr8Kq2Lm" * 5 + "'\n"})
    code, output = run(["pre-commit", "--no-roster"], capsys)
    assert code == 1
    assert "settings.py:1 secret.github_token" in output
    assert "WARN: running without a roster" in output


def test_missing_or_unconfigured_roster_blocks(repo, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    stage(repo, {"a.txt": "hello\n"})
    code, output = run(["pre-commit"], capsys)
    assert code == 1 and output.startswith("BLOCKED: no roster folder")
    code, output = run(["pre-commit", "--roster-dir", str(tmp_path / "nowhere")], capsys)
    assert code == 1 and "BLOCKED: roster key not found" in output


def test_unexpected_errors_fail_closed_without_details(repo, hook, monkeypatch):
    p = PATIENTS[0]

    def explode(*_args):
        raise RuntimeError(f"could not parse {p.full_name}")

    monkeypatch.setattr(precommit, "check_staged", explode)
    code, output = hook()
    assert code == 1
    assert "BLOCKED: phi-guardrails hit an unexpected error" in output
    assert_no_values(output)


def test_commit_message_check(roster_dir, tmp_path, capsys):
    p = PATIENTS[5]
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text(f"Fix eligibility retry\n\nReported by {p.full_name}\n", encoding="utf-8")
    code, output = run(["commit-msg", "--roster-dir", str(roster_dir), str(message)], capsys)
    assert code == 1
    assert "BLOCKED commit message:3 roster.name_pair" in output
    assert_no_values(output)

    message.write_text("Fix eligibility retry\n", encoding="utf-8")
    assert run(["commit-msg", "--roster-dir", str(roster_dir), str(message)], capsys) == (0, "")


# git's editor template for each cleanup mode, as git 2.55 writes it.
STRIP_HINT = ["# Please enter the commit message for your changes. Lines starting",
              "# with '#' will be ignored, and an empty message aborts the commit."]
KEEP_HINT = ["# Please enter the commit message for your changes. Lines starting",
             "# with '#' will be kept; you may remove them yourself if you want to.",
             "# An empty message aborts the commit."]
CUT = [f"# {precommit.SCISSORS}", "# Do not modify or remove the line above.", "# Everything below it will be ignored."]


def editor_message(p, hint: list[str], *, verbose: bool = True) -> str:
    """What commit-msg gets from an editor commit that deletes a patient-named export.

    The status block names the deleted file (a name_pair), and with "commit -v" the diff
    below the cut line has the file's rows (a name_dob too).
    """
    export = f"exports/{p.last}_{p.first}.csv"
    lines = ["Remove the old export", "", *hint, "#", "# Changes to be committed:", f"#\tdeleted:    {export}", "#"]
    if verbose:
        lines += [*CUT, f"diff --git a/{export} b/{export}", f"-{p.full_name},{p.dob}"]
    return "\n".join(lines) + "\n"


def test_commit_message_skips_what_git_says_it_will_drop(repo, roster_dir, monkeypatch, capsys):
    # git hands commit-msg the editor template before cleaning it up. Checking the file list or the
    # "commit -v" diff would block the very commit that removes a patient file.
    monkeypatch.chdir(repo)
    p = PATIENTS[4]
    message = repo / ".git" / "COMMIT_EDITMSG"
    argv = ["commit-msg", "--roster-dir", str(roster_dir), str(message)]
    # newline="" keeps git's LF line endings on Windows too.
    message.write_text(editor_message(p, STRIP_HINT), encoding="utf-8", newline="")
    assert run(argv, capsys) == (0, "")

    # The scissors mode puts the cut line above the file list.
    scissors = editor_message(p, CUT, verbose=False)
    message.write_text(scissors + f"diff --git a/x b/x\n-{p.full_name},{p.dob}\n", encoding="utf-8", newline="")
    assert run(argv, capsys) == (0, "")

    git(repo, "config", "core.commentChar", ";")
    message.write_text(editor_message(p, STRIP_HINT).replace("#", ";"), encoding="utf-8", newline="")
    assert run(argv, capsys) == (0, "")


def test_commit_message_checks_what_git_will_keep(repo, roster_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    p = PATIENTS[4]
    message = repo / ".git" / "COMMIT_EDITMSG"
    argv = ["commit-msg", "--roster-dir", str(roster_dir), str(message)]

    def check(text: str) -> set[str]:
        message.write_text(text, encoding="utf-8", newline="")
        code, output = run(argv, capsys)
        assert code == (1 if output else 0)
        return {line.split()[-1] for line in output.splitlines() if line.startswith("BLOCKED")}

    # Without an editor (-m, -F) git runs hooks with GIT_EDITOR=: and keeps every line.
    monkeypatch.setenv("GIT_EDITOR", ":")
    assert check(editor_message(p, STRIP_HINT)) == {"roster.name_pair", "roster.name_dob"}
    monkeypatch.delenv("GIT_EDITOR")
    # --cleanup=verbatim or whitespace keeps the file list, and cuts only with "-v", which a hook
    # can't see, so the diff is checked too.
    assert check(editor_message(p, KEEP_HINT)) == {"roster.name_pair", "roster.name_dob"}
    # A git that writes its template in another language: nothing says what it will drop.
    translated = editor_message(p, ["# Bitte geben Sie eine Commit-Beschreibung ein."])
    translated = translated.replace(CUT[1], "# Die Zeile oberhalb nicht ändern oder entfernen.")
    assert check(translated) == {"roster.name_pair", "roster.name_dob"}
    # A cut line without git's words under it is ordinary text to git, and so is one ending in
    # CRLF to Linux git.
    typed = f"Remove the old export\n# {precommit.SCISSORS}\n-{p.full_name},{p.dob}\n"
    assert check(typed) == {"roster.name_pair", "roster.name_dob"}
    assert "roster.name_dob" in check(editor_message(p, STRIP_HINT).replace("\n", "\r\n"))
    # Comment lines the template didn't write are checked when git keeps them.
    assert check(f"# note for {p.full_name}\n") == {"roster.name_pair"}
    # Copying git's "will be ignored" hint into a message changes nothing when git's own
    # template says the comment lines will be kept, and nothing at all for comment lines
    # outside the file list (the scissors mode writes no hint, and keeps them).
    copied = "\n".join(STRIP_HINT)
    note = f"Remove the old export\n{copied}\n# note for {p.full_name}\n"
    message.write_text(note + editor_message(p, KEEP_HINT, verbose=False), encoding="utf-8", newline="")
    code, output = run(argv, capsys)
    assert code == 1 and "BLOCKED commit message:4 roster.name_pair" in output
    assert check(note) == {"roster.name_pair"}
    # The same goes for a copied cut line: without "-v" git cuts nowhere, so only a cut line below
    # git's own hint counts, and none does after a "will be kept" hint.
    cut = "\n".join(CUT[:2])
    above = f"Remove the old export\n{cut}\n{p.full_name}\n"
    message.write_text(above + editor_message(p, STRIP_HINT, verbose=False), encoding="utf-8", newline="")
    code, output = run(argv, capsys)
    assert code == 1 and "BLOCKED commit message:4 roster.name_pair" in output
    assert check(above + editor_message(p, KEEP_HINT, verbose=False)) == {"roster.name_pair"}


def test_commit_message_in_windows_1252_is_read_not_garbled(tmp_path, capsys):
    # Replacement characters would turn an accented first name into one the roster doesn't know.
    folder = tmp_path / "accented"
    roster.init_key(folder / roster.KEY_FILE)
    export = tmp_path / "export.csv"
    export.write_text("first_name,last_name\nZoë,Quillfeather\n", encoding="utf-8")
    roster.build([export], folder)
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_bytes("Reported by Zoë Quillfeather\n".encode("cp1252"))
    code, output = run(["commit-msg", "--roster-dir", str(folder), str(message)], capsys)
    assert code == 1 and "commit message:1 roster.name_pair" in output


def test_an_unreadable_commit_message_is_blocked(repo, roster_dir, monkeypatch, capsys):
    monkeypatch.chdir(repo)
    message = repo / ".git" / "COMMIT_EDITMSG"
    argv = ["commit-msg", "--roster-dir", str(roster_dir), str(message)]
    message.write_bytes(b"fix\x00retry\n")
    code, output = run(argv, capsys)
    assert code == 1 and "BLOCKED commit message message.unreadable" in output
    # Naming an encoding doesn't make NUL bytes text.
    git(repo, "config", "i18n.commitEncoding", "UTF-8")
    code, output = run(argv, capsys)
    assert code == 1 and "BLOCKED commit message message.unreadable" in output

    # Read as UTF-16, plain text turns into characters no check matches, so that setting is not trusted.
    git(repo, "config", "i18n.commitEncoding", "UTF-16")
    text = f"call {PATIENTS[0].full_name}\n"
    message.write_bytes((text if len(text) % 2 == 0 else " " + text).encode("ascii"))
    code, output = run(argv, capsys)
    assert code == 1 and "roster.name_pair" in output


def test_install_hooks_respects_existing_hooks(repo):
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho someone else's hook\n", encoding="utf-8")
    with pytest.raises(precommit.ConfigError, match="already exists"):
        precommit.install_hooks(repo)
    assert not (hooks / "commit-msg").exists()

    written = precommit.install_hooks(repo, force=True)
    assert {path.name for path in written} == {"pre-commit", "pre-merge-commit", "commit-msg"}
    assert precommit.HOOK_MARK in (hooks / "pre-commit").read_text(encoding="utf-8")
    precommit.install_hooks(repo)  # reinstalling over its own hooks needs no --force


def test_installed_hooks_stop_a_real_commit(repo, roster_dir, tmp_path, monkeypatch):
    # The hook runs a fresh interpreter; point it at this checkout instead of requiring an install.
    # The trailing separator adds an empty entry, which Python reads as the current folder: the
    # repository being committed to. The json.py check at the end depends on it.
    monkeypatch.setenv("PYTHONPATH", str(PROJECT_ROOT) + os.pathsep)
    precommit.install_hooks(repo, roster_dir=roster_dir)
    p = PATIENTS[1]

    stage(repo, {"notes.txt": f"call {p.full_name} back\n"})
    blocked = subprocess.run(["git", "-C", str(repo), "commit", "-m", "add notes"], capture_output=True, text=True)
    assert blocked.returncode != 0
    assert "notes.txt:1 roster.name_pair" in blocked.stdout + blocked.stderr
    assert_no_values(blocked.stdout + blocked.stderr)

    git(repo, "rm", "-q", "--cached", "notes.txt")
    stage(repo, {"readme.txt": "hello\n"})
    bad_message = subprocess.run(["git", "-C", str(repo), "commit", "-m", f"readme for {p.full_name}"],
                                 capture_output=True, text=True)
    assert bad_message.returncode != 0
    assert "commit message:1 roster.name_pair" in bad_message.stdout + bad_message.stderr

    # "commit -m" keeps a line that looks like the editor template's file list, so the hook checks it.
    template_like = subprocess.run(["git", "-C", str(repo), "commit", "-m", f"readme\n\n#\tsee {p.full_name}"],
                                   capture_output=True, text=True)
    assert template_like.returncode != 0
    assert "commit message:3 roster.name_pair" in template_like.stdout + template_like.stderr

    ok = subprocess.run(["git", "-C", str(repo), "commit", "-m", "add readme"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    # Cleaning up with an editor commit: git's template lists the removed path in a comment.
    old_export = f"exports/{p.last}_{p.first}.csv"
    commit(repo, {old_export: "visit_count\n3\n"}, "old export")
    git(repo, "rm", "-q", old_export)
    editor = tmp_path / "editor.py"
    editor.write_text("import sys\n"
                      "path = sys.argv[1]\n"
                      "text = open(path, encoding='utf-8').read()\n"
                      "open(path, 'w', encoding='utf-8', newline='').write('Remove the old export\\n' + text)\n",
                      encoding="utf-8")
    env = dict(os.environ, GIT_EDITOR=f'"{Path(sys.executable).as_posix()}" "{editor.as_posix()}"')
    # --cleanup=verbatim keeps that comment in the commit, and hooks can't see the option,
    # but git's template says so.
    kept = subprocess.run(["git", "-C", str(repo), "commit", "--cleanup=verbatim"],
                          capture_output=True, text=True, env=env)
    assert kept.returncode != 0
    assert "roster.name_pair" in kept.stdout + kept.stderr
    # The default cleanup drops it, and "-v" adds a diff that git cuts off.
    removed = subprocess.run(["git", "-C", str(repo), "commit", "-v"], capture_output=True, text=True, env=env)
    assert removed.returncode == 0, removed.stdout + removed.stderr
    assert "\n#" not in git(repo, "log", "-1", "--format=%B")

    # The hook ignores a json.py in the repository instead of importing it over the stdlib.
    commit(repo, {"json.py": "raise SystemExit('shadowed the stdlib')\n"}, "add a module named json")
    stage(repo, {"notes.txt": "nothing sensitive\n"})
    shadowed = subprocess.run(["git", "-C", str(repo), "commit", "-m", "notes"], capture_output=True, text=True)
    assert shadowed.returncode == 0, shadowed.stdout + shadowed.stderr
