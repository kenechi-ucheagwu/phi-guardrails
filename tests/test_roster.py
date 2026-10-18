"""Roster build, load and matching. All data is synthetic (see fakes.py)."""
from __future__ import annotations

import csv
import io
import json
import os
import re

import pytest
from fakes import FIRST_NAMES, PATIENTS, STAFF_FIRST, STAFF_LAST, SURNAMES, staff_name, write_exports

from phi_guardrails import roster
from phi_guardrails.errors import RosterError


def _edit_roster(roster_dir, **changes):
    path = roster_dir / roster.ROSTER_FILE
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.update(changes)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _roster_from(tmp_path, header, rows, *, encoding="utf-8", staff_lines=None):
    """Build and load a roster from one CSV with the given header and rows."""
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    buffer = io.StringIO(newline="")
    csv.writer(buffer).writerows([header, *rows])
    export = tmp_path / "export.csv"
    export.write_bytes(buffer.getvalue().encode(encoding))
    staff = None
    if staff_lines:
        staff = tmp_path / "staff.txt"
        staff.write_text("\n".join(staff_lines) + "\n", encoding="utf-8")
    roster.build([export], folder, staff_file=staff)
    return roster.load(folder)


def test_build_counts_patients_and_skips_staff_and_stop_words(loaded):
    assert len(loaded.pairs) == len(PATIENTS)
    assert len(loaded.members) == len(PATIENTS)
    assert len(loaded.name_dob) == len(PATIENTS)


def test_roster_file_holds_no_plain_text(roster_dir):
    stored = (roster_dir / roster.ROSTER_FILE).read_text(encoding="utf-8").upper()
    for p in PATIENTS:
        for value in (p.first, p.last, p.member_id, p.dob):
            # Whole tokens only: a short name like "Ada" is all hex letters and
            # can turn up inside a digest by chance.
            assert not re.search(rf"(?<![0-9A-Z]){re.escape(value.upper())}(?![0-9A-Z])", stored)


NAME_FORMS = [
    lambda p: p.full_name,
    lambda p: f"{p.last}, {p.first}",
    lambda p: f"{p.first} Q. {p.last}",
    lambda p: f"{p.first} Mae {p.last}",
    lambda p: f"{p.last.upper()} {p.first.upper()}",
    lambda p: f"exports/note_for_{p.first.lower()}_{p.last.lower()}.txt",
    lambda p: f"scans/{p.first.lower()}-{p.last.lower()}-labs.pdf",
]


@pytest.mark.parametrize("form", NAME_FORMS)
def test_name_pair_matches_common_forms(loaded, form):
    for p in PATIENTS:
        assert "name_pair" in loaded.check_line(form(p))


@pytest.mark.parametrize("line", [
    lambda p: f"{p.first} called about the {p.last} account",
    lambda p: f"{p.first} only",
    lambda p: f"{p.last} only",
    lambda p: "TEST PATIENT and Test, Patient",
    lambda p: f"{staff_name()} signed the note",
])
def test_name_pair_ignores_near_misses_staff_and_stop_words(loaded, line):
    assert loaded.check_line(line(PATIENTS[0])) == []


def test_mixed_up_first_and_last_names_do_not_match(loaded):
    assert loaded.check_line(f"{FIRST_NAMES[0]} {SURNAMES[1]}") == []


@pytest.mark.parametrize("form", [
    lambda p: f'Patient(first_name="{p.first}", last_name="{p.last}")',
    lambda p: f'{{"first_name": "{p.first}", "middle_name": "Q", "last_name": "{p.last}"}}',
    lambda p: f"{p.first} {p.last} Jr.",
])
def test_name_pair_sees_through_field_labels_and_suffixes(loaded, form):
    for p in PATIENTS:
        assert "name_pair" in loaded.check_line(form(p))


def test_member_id_matches_in_any_case(loaded):
    p = PATIENTS[3]
    assert loaded.check_line(f"eligibility for {p.member_id} confirmed") == ["member_id"]
    assert loaded.check_line(p.member_id.lower()) == ["member_id"]


@pytest.mark.parametrize("form", [
    lambda m: f"eligibility-{m}.json",
    lambda m: f"{m}-01",
    lambda m: f"{m[:3]}-{m[3:]}",
    lambda m: f"eligibility-{m[:3]}-{m[3:]}.json",
    lambda m: f"{m[:3]}-{m[3:]}-01",
])
def test_member_id_matches_inside_hyphenated_tokens(loaded, form):
    for p in PATIENTS:
        assert "member_id" in loaded.check_line(form(p.member_id))


@pytest.mark.parametrize("date_form", ["dob", "dob_us"])
def test_name_and_birth_date_on_one_line(loaded, date_form):
    for p in PATIENTS:
        line = f"{p.full_name} born {getattr(p, date_form)}"
        assert loaded.check_line(line) == ["name_pair", "name_dob"]


def test_wrong_birth_date_gives_only_the_name_pair(loaded):
    p = PATIENTS[0]
    assert loaded.check_line(f"{p.full_name} 01/01/1900") == ["name_pair"]


def test_birth_dates_rejects_invalid_and_recent_dates():
    assert roster.birth_dates("13/45/1990 2020-01-01 02/30/1999") == set()
    assert roster.birth_dates("07/30/1988 and 1961-03-14") == {"1988-07-30", "1961-03-14"}


def test_birth_dates_accept_unpadded_and_timestamped_forms():
    assert roster.birth_dates("7/3/1988, 1961-3-4 and 1974-11-02T00:00:00") == {
        "1988-07-03", "1961-03-04", "1974-11-02"}
    assert roster.birth_dates("119610314 and 1961-03-145") == set()


def test_exports_with_other_headers_and_unicode_text(tmp_path):
    p = PATIENTS[0]
    month, day, year = p.dob_us.split("/")
    header = ["PatientFirstName", "PatientLastName", "Patient DOB", "Subscriber ID"]
    for encoding in ("utf-8", "utf-16"):
        folder = tmp_path / encoding
        folder.mkdir()
        loaded = _roster_from(folder, header, [[p.first, p.last, f"{int(month)}/{int(day)}/{year}", p.member_id]],
                              encoding=encoding)
        assert loaded.check_line(f"{p.full_name} {p.dob}") == ["name_pair", "name_dob"]
        assert loaded.check_line(p.member_id) == ["member_id"]


def test_accents_and_curly_apostrophes_match_plain_spellings(tmp_path):
    accented = FIRST_NAMES[4][:2] + "é" + FIRST_NAMES[4][3:]
    curly = "O’" + SURNAMES[3]
    loaded = _roster_from(tmp_path, ["first_name", "last_name"], [[accented, curly]])
    for line in (f"{accented} {curly}", f"{FIRST_NAMES[4]} O'{SURNAMES[3]}", f"{FIRST_NAMES[4]} O{SURNAMES[3]}"):
        assert loaded.check_line(line) == ["name_pair"]


def test_suffix_in_the_surname_column_is_dropped(tmp_path):
    loaded = _roster_from(tmp_path, ["Patient Name"], [[f"{SURNAMES[5]} Jr, {FIRST_NAMES[1]}"]])
    assert loaded.check_line(f"{FIRST_NAMES[1]} {SURNAMES[5]}") == ["name_pair"]


@pytest.mark.parametrize("value", [
    lambda first, last: f"{first} {last}, Jr.",
    lambda first, last: f"{last}, {first}, III",
])
def test_a_suffix_after_a_comma_is_not_read_as_a_first_name(tmp_path, value):
    loaded = _roster_from(tmp_path, ["Patient Name"], [[value(FIRST_NAMES[2], SURNAMES[4])]])
    assert loaded.check_line(f"{FIRST_NAMES[2]} {SURNAMES[4]}") == ["name_pair"]


def test_staff_titles_and_credentials_are_ignored(tmp_path):
    rows = [[f"{STAFF_LAST}, {STAFF_FIRST}"], [f"{SURNAMES[2]}, {FIRST_NAMES[2]}"]]
    for number, line in enumerate([f"Dr. {STAFF_FIRST} {STAFF_LAST}, MD", f"{STAFF_LAST}, {STAFF_FIRST}, RN, BSN"]):
        folder = tmp_path / f"case{number}"
        folder.mkdir()
        loaded = _roster_from(folder, ["Patient Name"], rows, staff_lines=[line])
        assert loaded.check_line(staff_name()) == []
        assert loaded.check_line(f"{FIRST_NAMES[2]} {SURNAMES[2]}") == ["name_pair"]


def test_merge_keeps_patients_from_deleted_exports(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    week1, week2 = PATIENTS[:2], PATIENTS[2:4]
    roster.build(write_exports(tmp_path / "week1", week1), folder)
    roster.build(write_exports(tmp_path / "week2", week2), folder, merge=True)
    merged = roster.load(folder)
    assert all(merged.check_line(p.full_name) == ["name_pair"] for p in week1 + week2)

    roster.build(write_exports(tmp_path / "week3", week2), folder)
    assert roster.load(folder).check_line(week1[0].full_name) == []


def test_merge_still_drops_newly_listed_staff(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    roster.build(write_exports(tmp_path / "exports"), folder)
    assert roster.load(folder).check_line(staff_name()) == ["name_pair"]
    staff = tmp_path / "staff.txt"
    staff.write_text(staff_name() + "\n", encoding="utf-8")
    roster.build([tmp_path / "exports"], folder, staff_file=staff, merge=True)
    assert roster.load(folder).check_line(staff_name()) == []


def test_windows_1252_export_is_read(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    first = "Zoë"
    export = tmp_path / "legacy.csv"
    export.write_bytes(("first_name,last_name\r\n" + ",".join([first, SURNAMES[0]]) + "\r\n").encode("cp1252"))
    roster.build([export], folder)
    for spelling in (first, "Zoe"):
        assert roster.load(folder).check_line(f"{spelling} {SURNAMES[0]}") == ["name_pair"]


def test_build_needs_a_key(tmp_path):
    write_exports(tmp_path / "exports")
    with pytest.raises(RosterError, match="key not found"):
        roster.build([tmp_path / "exports"], tmp_path / "roster")


def test_build_stops_on_a_csv_without_name_columns(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    exports = write_exports(tmp_path / "exports")
    counts = tmp_path / "exports" / "counts.csv"
    counts.write_text("clinic,visits\nnorth,12\n", encoding="utf-8")
    with pytest.raises(RosterError, match="1 CSV file.s. had no recognizable patient name columns"):
        roster.build([tmp_path / "exports"], folder)
    assert not (folder / roster.ROSTER_FILE).exists()

    assert roster.build([tmp_path / "exports"], folder, allow_empty=True)["files"] == len(exports) + 1
    with pytest.raises(RosterError, match="no patient names found"):
        roster.build([counts], folder, allow_empty=True)


def test_build_errors_mask_exports_named_after_patients(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    write_exports(tmp_path / "exports")
    p = PATIENTS[0]
    (tmp_path / "exports" / f"{p.last}_{p.first}.csv").write_text("clinic,visits\nnorth,12\n", encoding="utf-8")
    (tmp_path / "exports" / "counts.csv").write_text("clinic,visits\nsouth,4\n", encoding="utf-8")
    with pytest.raises(RosterError) as caught:
        roster.build([tmp_path / "exports"], folder)
    message = str(caught.value)
    assert "2 CSV file(s)" in message and "<masked:" in message and "counts.csv" in message
    assert p.last not in message and p.first not in message


def test_build_errors_also_mask_names_the_existing_roster_knows(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    write_exports(tmp_path / "exports")
    roster.build([tmp_path / "exports"], folder)
    p = PATIENTS[0]
    # This build's own exports don't name the patient, but the roster already on disk does.
    write_exports(tmp_path / "later", [PATIENTS[1]])
    (tmp_path / "later" / f"{p.last}_{p.first}.csv").write_text("clinic,visits\nnorth,12\n", encoding="utf-8")
    with pytest.raises(RosterError) as caught:
        roster.build([tmp_path / "later"], folder)
    message = str(caught.value)
    assert "1 CSV file(s)" in message and "<masked:" in message
    assert p.last not in message and p.first not in message


def test_build_leaves_no_temporary_files(roster_dir):
    assert sorted(p.name for p in roster_dir.iterdir()) == sorted([roster.KEY_FILE, roster.ROSTER_FILE])


def test_build_reports_missing_source(tmp_path):
    folder = tmp_path / "roster"
    roster.init_key(folder / roster.KEY_FILE)
    with pytest.raises(RosterError, match="source #1 does not exist"):
        roster.build([tmp_path / "missing.csv"], folder)


def test_init_key_never_overwrites(tmp_path):
    path = roster.init_key(tmp_path / roster.KEY_FILE)
    original = path.read_bytes()
    with pytest.raises(RosterError, match="already exists"):
        roster.init_key(path)
    assert path.read_bytes() == original


def test_load_rejects_wrong_key_length(roster_dir):
    (roster_dir / roster.KEY_FILE).write_bytes(os.urandom(31))
    with pytest.raises(RosterError, match="wrong length"):
        roster.load(roster_dir)


def test_load_rejects_a_different_key(roster_dir):
    (roster_dir / roster.KEY_FILE).write_bytes(os.urandom(32))
    with pytest.raises(RosterError, match="different key"):
        roster.load(roster_dir)


@pytest.mark.parametrize("changes, message", [
    ({"version": 2}, "version"),
    ({"version": True}, "version"),
    ({"pairs": ["not-a-digest"]}, "'pairs' is invalid"),
    ({"members": "0" * 64}, "'members' is invalid"),
    ({"pairs": []}, "no name pairs"),
    ({"built_at": "2026-01-01T00:00:00"}, "timestamp"),
    ({"built_at": 12}, "timestamp"),
])
def test_load_rejects_damaged_rosters(roster_dir, changes, message):
    _edit_roster(roster_dir, **changes)
    with pytest.raises(RosterError, match=message) as caught:
        roster.load(roster_dir)
    for p in PATIENTS:
        assert p.last not in str(caught.value)


def test_load_rejects_unreadable_json(roster_dir):
    (roster_dir / roster.ROSTER_FILE).write_text("{not json", encoding="utf-8")
    with pytest.raises(RosterError, match="could not be read"):
        roster.load(roster_dir)


def test_old_roster_warns_but_loads(roster_dir, capsys):
    _edit_roster(roster_dir, built_at="2020-01-01T00:00:00+00:00")
    assert roster.load(roster_dir).pairs
    assert "more than 14 days old" in capsys.readouterr().err


def test_repr_shows_counts_not_key(loaded):
    text = repr(loaded)
    assert "pairs=6" in text and loaded.key.hex() not in text
