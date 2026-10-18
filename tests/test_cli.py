"""Command-line behavior: help, exit codes, and the init-key / build / check flow."""
from __future__ import annotations

import io
import os
import subprocess
import sys

import pytest
from fakes import PATIENTS, PROJECT_ROOT, assert_no_values, staff_name, write_exports

from phi_guardrails import __version__, cli

COMMANDS = ["init-key", "build", "check", "install-hooks", "pre-commit", "commit-msg", "scan-history"]


@pytest.mark.parametrize("argv", [["--help"], *([command, "--help"] for command in COMMANDS)])
def test_help_exits_zero(argv, capsys):
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)
    assert caught.value.code == 0
    assert "usage: phi-guard" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_usage_errors_exit_two():
    with pytest.raises(SystemExit) as caught:
        cli.main(["no-such-command"])
    assert caught.value.code == 2


def test_module_entry_point():
    env = dict(os.environ, PYTHONPATH=str(PROJECT_ROOT))
    result = subprocess.run([sys.executable, "-m", "phi_guardrails", "--help"], capture_output=True, text=True,
                            env=env)
    assert result.returncode == 0 and "scan-history" in result.stdout


def test_key_build_and_check_flow(tmp_path, capsys):
    roster_dir = str(tmp_path / "roster")
    assert cli.main(["init-key", "--roster-dir", roster_dir]) == 0
    assert cli.main(["init-key", "--roster-dir", roster_dir]) == 2
    assert "refusing to replace it" in capsys.readouterr().err

    write_exports(tmp_path / "exports")
    staff = tmp_path / "staff.txt"
    staff.write_text(staff_name() + "\n", encoding="utf-8")
    assert cli.main(["build", "--roster-dir", roster_dir, "--staff", str(staff), str(tmp_path / "exports")]) == 0
    built = capsys.readouterr().out
    assert all(count in built for count in ("6 name pairs", "6 member IDs", "6 name+DOB"))

    p = PATIENTS[0]
    flagged = tmp_path / "script.py"
    flagged.write_text(f"# TODO remove\nWHO = '{p.last}, {p.first}'\n", encoding="utf-8")
    clean = tmp_path / "clean.py"
    clean.write_text("print('ok')\n", encoding="utf-8")
    image = tmp_path / "shot.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(8))

    assert cli.main(["check", "--roster-dir", roster_dir, str(clean)]) == 0
    assert cli.main(["check", "--roster-dir", roster_dir, str(flagged), str(image)]) == 1
    output = capsys.readouterr().out
    assert "script.py:2 roster.name_pair" in output
    assert "shot.png binary.not_scanned" in output
    assert_no_values(output)


def test_env_var_supplies_the_roster(roster_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PHI_ROSTER_DIR", str(roster_dir))
    target = tmp_path / "x.txt"
    target.write_text(PATIENTS[2].full_name + "\n", encoding="utf-8")
    assert cli.main(["check", str(target)]) == 1
    assert "x.txt:1 roster.name_pair" in capsys.readouterr().out


def test_output_survives_a_console_that_cannot_encode_the_path(roster_dir, tmp_path, monkeypatch):
    # Piped output on Windows is often cp1252; a non-Latin file name must not crash the report.
    target = tmp_path / "日本.txt"
    target.write_text(PATIENTS[2].full_name + "\n", encoding="utf-8")
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="cp1252"))
    assert cli.main(["check", "--roster-dir", str(roster_dir), str(target)]) == 1
    sys.stdout.flush()
    assert b"roster.name_pair" in buffer.getvalue()


def test_setup_errors_exit_two(tmp_path, capsys):
    target = tmp_path / "x.txt"
    target.write_text("hello\n", encoding="utf-8")
    assert cli.main(["check", str(target)]) == 2
    assert "no roster folder" in capsys.readouterr().err
    assert cli.main(["check", "--no-roster", str(tmp_path / "missing.txt")]) == 2
    assert "cannot read" in capsys.readouterr().err
