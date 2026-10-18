from __future__ import annotations

from pathlib import Path

import pytest
from fakes import git, staff_name, write_exports

from phi_guardrails import roster
from phi_guardrails.scanner import Scanner

# Variables that would point git at some other repository, index or config.
GIT_REDIRECTS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                 "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_EDITOR")


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    """No roster from the environment, and git that can't see the developer's config or repositories.

    pytest's temporary folders can sit inside a repository (a dotfiles repo in
    the home folder, or the outer repo when the tests run from a git hook), so
    git is stopped from searching above each test's own folder.
    """
    for name in ("PHI_ROSTER_DIR", "PHI_GUARD_DEBUG", *GIT_REDIRECTS):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "gitconfig"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "fixture-bot")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "fixture-bot@example.invalid")


@pytest.fixture
def roster_dir(tmp_path) -> Path:
    """A roster built from synthetic exports, with one staff member left out."""
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    staff = tmp_path / "staff.txt"
    staff.write_text(staff_name() + "\n", encoding="utf-8")
    write_exports(tmp_path / "exports")
    roster.build([tmp_path / "exports"], folder, staff_file=staff)
    return folder


@pytest.fixture
def loaded(roster_dir) -> roster.Roster:
    return roster.load(roster_dir)


@pytest.fixture
def scanner(loaded) -> Scanner:
    return Scanner(loaded)


@pytest.fixture
def repo(tmp_path) -> Path:
    """An empty repository, isolated from the developer's global git config, hooks and signing."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q")
    return path
