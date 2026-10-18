"""Synthetic people and small git helpers shared by the tests.

Every name, date and ID here is invented. First names and surnames live in
separate lists and are only combined at runtime, so no single line of this
repository holds a full synthetic patient name, and member IDs are generated
rather than written out. That keeps the repository's own history scan clean,
even when it runs with the test roster loaded.
"""
from __future__ import annotations

import csv
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

FIRST_NAMES = ["Ada", "Bram", "Cleo", "Dov", "Ines", "Juno"]
SURNAMES = ["Fixtureson", "Mockwell", "Synthetica", "Placeholdr", "Testwood", "Sampleby"]
BIRTH_DATES = ["1961-03-14", "1974-11-02", "1988-07-30", "1993-01-09", "1952-05-21", "2004-12-17"]
STAFF_FIRST = "Hollis"
STAFF_LAST = "Clinicwright"


@dataclass(frozen=True)
class FakePatient:
    first: str
    last: str
    dob: str
    member_id: str

    @property
    def full_name(self) -> str:
        return f"{self.first} {self.last}"

    @property
    def dob_us(self) -> str:
        year, month, day = self.dob.split("-")
        return f"{month}/{day}/{year}"

    def values(self) -> list[str]:
        """Strings that must never appear in any output."""
        return [self.full_name, self.last, self.dob, self.dob_us, self.member_id]


PATIENTS = [
    FakePatient(first, last, born, f"ZZT{40001 + i}")
    for i, (first, last, born) in enumerate(zip(FIRST_NAMES, SURNAMES, BIRTH_DATES))
]


def staff_name() -> str:
    return f"{STAFF_FIRST} {STAFF_LAST}"


def write_exports(folder: Path, patients: list[FakePatient] = PATIENTS) -> list[Path]:
    """Two CSVs shaped like EHR and eligibility exports, using different headers."""
    folder.mkdir(parents=True, exist_ok=True)
    visits, eligibility = folder / "visits.csv", folder / "eligibility.csv"
    half = len(patients) // 2
    with visits.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Patient Name", "DOB", "Member ID", "Visit Type"])
        for p in patients[:half]:
            writer.writerow([f"{p.last}, {p.first}", p.dob_us, p.member_id, "follow-up"])
        writer.writerow(["Test, Patient", "", "", "follow-up"])
        writer.writerow([f"{STAFF_LAST}, {STAFF_FIRST}", "", "", "employee visit"])
    with eligibility.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["first_name", "last_name", "date_of_birth", "subscriber_id"])
        for p in patients[half:]:
            writer.writerow([p.first, p.last, p.dob, p.member_id])
    return [visits, eligibility]


def assert_no_values(text: str, *patients: FakePatient) -> None:
    for patient in patients or PATIENTS:
        for value in patient.values():
            assert value not in text


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True, text=True).stdout


def stage(repo: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    git(repo, "add", "--", *files)


def commit(repo: Path, files: dict[str, str | bytes], message: str = "update") -> None:
    """Commit without hooks, to build history the way an unprotected repo would have it."""
    stage(repo, files)
    git(repo, "commit", "-q", "--no-verify", "-m", message)
