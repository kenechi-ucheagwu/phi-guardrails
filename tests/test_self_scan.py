"""This repository passes its own checks, with the synthetic test roster loaded.

CI runs scan-history on the repository without a roster. This test covers the
part CI can't: no file here holds a synthetic patient's full name, member ID
or name+DOB on one line, and no file path names one.
"""
from __future__ import annotations

from fakes import PROJECT_ROOT

from phi_guardrails.scanner import decode_text

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "build", "dist"}


def project_files():
    for path in sorted(PROJECT_ROOT.rglob("*")):
        relative = path.relative_to(PROJECT_ROOT)
        if path.is_file() and not any(part in SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts):
            yield relative.as_posix()


def test_every_project_file_passes_its_own_scan(scanner):
    files = list(project_files())
    assert "phi_guardrails/roster.py" in files and "README.md" in files
    findings = []
    for name in files:
        text = decode_text((PROJECT_ROOT / name).read_bytes())
        assert text is not None, f"{name} is not UTF-8 text"
        if scanner.path_hit(name):
            findings.append(f"{name} roster.path")
        findings += [f"{name}:{number} {category}" for number, category in scanner.check_text(text)]
    assert findings == []
