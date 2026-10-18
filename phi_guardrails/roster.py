"""Keyed-hash patient roster.

The roster holds HMAC-SHA256 digests of three things taken from patient
exports: first+last name pairs, member IDs, and name+date-of-birth
combinations. Checking a line means normalizing its words the same way,
hashing them with the same key, and looking the digests up.

The key is what makes the roster file safe to have lying around. Plain SHA-256
digests of names could be reversed by hashing a list of common names. HMAC
digests can't be tested against guesses without the 32-byte key. Keep both
files in a folder outside every repository, readable only by the people who
run the checks.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

from .errors import RosterError

KEY_FILE = "roster.key"
ROSTER_FILE = "roster.v1.json"
KEY_BYTES = 32
MAX_AGE = timedelta(days=14)
DIGEST_FIELDS = ("pairs", "members", "name_dob")

WORD = re.compile(r"[A-Za-z][A-Za-z'\-]+")
MEMBER = re.compile(r"[A-Za-z0-9\-]{6,}")
MEMBER_KEY = re.compile(r"[A-Z0-9]{6,}")
DATE = re.compile(r"(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2}-\d{1,2}-\d{4})(?!\d)")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
# Words that turn up in name columns without being names.
STOP_WORDS = frozenset("THE AND FOR NOT NONE NULL UNKNOWN TEST PATIENT SELF NAN".split())
# Dropped before the first and last word of a name are picked, so "Smith Jr, John" is JOHN|SMITH.
SUFFIXES = frozenset("JR SR II III IV".split())
# Field labels between a first and a last name, as in first_name="..", last_name="..".
LABELS = frozenset("FIRST LAST MIDDLE NAME NAMES GIVEN FAMILY SURNAME FIRSTNAME LASTNAME FULLNAME".split())
# Titles and credentials that follow staff names ("Jane Smith, MD"). Staff lists only:
# some of these are real surnames, so patient names keep them.
CREDENTIALS = frozenset("""
    DR MR MRS MS MX MD DO NP RN PA PAC APRN FNP DNP CNM CRNA PHD PSYD LPN LCSW LMSW LPC MA CMA RMA MSN BSN
""".split())
_APOSTROPHES = str.maketrans({"’": "'", "‘": "'", "ʼ": "'"})


def _header_set(people: tuple[str, ...], fields: tuple[str, ...],
                exclude: frozenset[str] = frozenset()) -> frozenset[str]:
    return frozenset(person + field for person in people for field in fields) - exclude


# CSV headers seen in EHR, billing and eligibility exports, compared after dropping case
# and everything but letters and digits ("Date of Birth" -> "dateofbirth").
_PEOPLE = ("", "patient", "pt", "member", "subscriber", "insured", "guarantor")
FULL_NAME = _header_set(_PEOPLE, ("name", "fullname"), exclude=frozenset({"name"})) | {"nameoncard"}
FIRST_NAME = _header_set(_PEOPLE, ("firstname", "first", "fname", "givenname"))
LAST_NAME = _header_set(_PEOPLE, ("lastname", "last", "lname", "surname", "familyname"))
BIRTH_DATE = _header_set(_PEOPLE, ("dob", "dateofbirth", "birthdate", "birthday"))
MEMBER_ID = frozenset({"memberid", "membernumber", "subscriberid", "subscribernumber", "insuredid", "policynumber",
                       "policyid", "insuranceid", "medicaidid", "medicareid", "mbi"})


def fold(text: str) -> str:
    """Strip accents and straighten curly apostrophes, so José O’Brien is stored as JOSE OBRIEN."""
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text.translate(_APOSTROPHES))
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def words(text: str) -> list[str]:
    """Name-like words in order, uppercased, with apostrophes and hyphens removed."""
    return [re.sub(r"[^A-Z]", "", m.group().upper()) for m in WORD.finditer(fold(text))]


def name_words(text: str) -> list[str]:
    return [w for w in words(text) if w not in SUFFIXES]


def pair_key(a: str, b: str) -> str | None:
    """Order-free key for two words, so "Last First" and "First Last" match."""
    if len(a) < 2 or len(b) < 2 or a in STOP_WORDS or b in STOP_WORDS:
        return None
    return "|".join(sorted((a, b)))


def name_pair(value: str) -> str | None:
    """First word plus last word of a name. Handles "Last, First Middle" too.

    A comma part that is only a suffix is dropped first, so "First Last, Jr."
    still reads as first-name-first.
    """
    parts = [part for part in map(name_words, value.split(",")) if part]
    if len(parts) >= 2:
        return pair_key(parts[1][0], parts[0][-1])
    tokens = parts[0] if parts else []
    return pair_key(tokens[0], tokens[-1]) if len(tokens) >= 2 else None


def member_key(value: str) -> str | None:
    """A member ID in stored form: uppercase, no hyphens, 6+ characters, at least one digit."""
    value = value.strip().upper().replace("-", "")
    if not MEMBER_KEY.fullmatch(value) or not any(c.isdigit() for c in value) or not value.strip("X"):
        return None
    return value


def member_candidates(text: str) -> Iterator[str]:
    """ID-shaped tokens, plus runs of up to four of their hyphen-separated parts.

    That covers eligibility-<id>.json and <id>-01, and an ID written with its
    own hyphens inside a longer name, like eligibility-AB-1234567.json.
    """
    for token in MEMBER.findall(text):
        yield token
        parts = [part for part in token.split("-") if part]
        if len(parts) > 1:
            for start in range(len(parts)):
                for end in range(start + 1, min(len(parts), start + 4) + 1):
                    yield "".join(parts[start:end])


def birth_dates(text: str) -> set[str]:
    """Valid dates before 2020 as ISO strings.

    Later dates are mostly visit and claim dates. A child born after 2019 is
    still caught by the name pair check; only the name+DOB category is lost.
    """
    found = set()
    for match in DATE.finditer(text):
        parts = re.split(r"[/\-]", match.group())
        year, month, day = parts if len(parts[0]) == 4 else (parts[2], parts[0], parts[1])
        try:
            parsed = date(int(year), int(month), int(day))
        except ValueError:
            continue
        if parsed.year < 2020:
            found.add(parsed.isoformat())
    return found


@lru_cache(maxsize=200_000)
def digest(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def mask(key: bytes, text: str) -> str:
    """A short keyed stand-in for a path that names a patient.

    A plain hash of a path like exports/Last_First.csv could be reversed by
    hashing guessed names; this one can't without the roster key.
    """
    keyed = hmac.new(key, text.encode("utf-8", "surrogateescape"), hashlib.sha256)
    return f"<masked:{keyed.hexdigest()[:12]}>"


def key_id(key: bytes) -> str:
    """A fingerprint of the key, stored in the roster so a mismatched pair is caught on load."""
    return hmac.new(key, b"phi-guardrails key id", hashlib.sha256).hexdigest()


def init_key(path: Path) -> Path:
    """Write a new random key. Never replaces an existing one, since that would orphan the roster."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise RosterError("a roster key already exists there; refusing to replace it") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(os.urandom(KEY_BYTES))
    return path


def read_key(path: Path) -> bytes:
    try:
        key = Path(path).read_bytes()
    except FileNotFoundError:
        raise RosterError("roster key not found; run 'phi-guard init-key' first") from None
    except OSError:
        raise RosterError("roster key could not be read") from None
    if len(key) != KEY_BYTES:
        raise RosterError("roster key has the wrong length")
    return key


def build(sources: Iterable[Path], roster_dir: Path, *, staff_file: Path | None = None,
          merge: bool = False, allow_empty: bool = False) -> dict[str, int]:
    """Hash every patient identifier found in the CSV sources into the roster file.

    sources: CSV files, or folders searched recursively for *.csv.
    staff_file: one staff name per line. Their name pairs are left out, so a
        clinician's name in a commit is not treated as a patient's.
    merge: also keep every digest already in the roster. Scheduled rebuilds
        should use it, so deleting an old export never shrinks coverage.
    allow_empty: skip CSV files with no recognizable name columns instead of
        stopping. By default such a file stops the build, because a header the
        tool doesn't know would otherwise drop every patient in it unnoticed.

    Returns the number of digests in each set, plus the number of CSV files read.
    Nothing is written in plain text.
    """
    roster_dir = Path(roster_dir)
    key = read_key(roster_dir / KEY_FILE)
    staff = _staff_pairs(staff_file) if staff_file else set()
    found: dict[str, set[str]] = {name: set() for name in DIGEST_FIELDS}
    files = _csv_files(sources)
    empty = []
    for path in files:
        if not sum(_collect(row, key, staff, found) for row in _rows(path)):
            empty.append(path)
    previous = None
    if (roster_dir / ROSTER_FILE).exists():
        try:
            previous = load(roster_dir, warn=False)
        except RosterError:
            if merge:
                raise
    if merge and previous is not None:
        found["pairs"] |= previous.pairs - {digest(key, p) for p in staff}
        found["members"] |= previous.members
        found["name_dob"] |= previous.name_dob
    if empty and not allow_empty:
        # An export is often named after its patient. Names this build found, or the roster
        # already on disk knows, are masked.
        known = Roster(key, *(frozenset(found[name]) | (getattr(previous, name) if previous else frozenset())
                              for name in DIGEST_FIELDS))
        shown = [mask(key, str(p)) if known.check_line(str(p)) else str(p) for p in empty[:5]]
        listed = ", ".join(shown) + (", ..." if len(empty) > 5 else "")
        raise RosterError(f"{len(empty)} CSV file(s) had no recognizable patient name columns: {listed}. "
                          "Check their headers, or pass --allow-empty to skip them")
    if not found["pairs"]:
        raise RosterError("no patient names found; check the CSV column headers")
    payload = {
        "version": 1,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "key_id": key_id(key),
        **{name: sorted(values) for name, values in found.items()},
    }
    _write_atomic(roster_dir / ROSTER_FILE, json.dumps(payload, sort_keys=True) + "\n")
    return {**{name: len(values) for name, values in found.items()}, "files": len(files)}


def _csv_files(sources: Iterable[Path]) -> list[Path]:
    files = []
    for number, source in enumerate(sources, 1):
        source = Path(source)
        if source.is_dir():
            files.extend(sorted(p for p in source.rglob("*") if p.is_file() and p.suffix.lower() == ".csv"))
        elif source.is_file():
            files.append(source)
        else:
            raise RosterError(f"source #{number} does not exist")
    return files


def _rows(path: Path) -> Iterator[dict[str, str]]:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        # Excel's "Unicode text" export and PowerShell 5.1 both write UTF-16.
        text = raw.decode("utf-16", errors="replace")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            # Older exports are often Windows-1252. Skipping them would silently drop patients.
            text = raw.decode("cp1252", errors="replace")
    # Note fields in some exports are larger than the csv module's 128 KB default.
    csv.field_size_limit(64 * 1024 * 1024)
    for row in csv.DictReader(io.StringIO(text, newline="")):
        yield {re.sub(r"[^a-z0-9]", "", k.lower()): (v or "").strip() for k, v in row.items() if isinstance(k, str)}


def _collect(row: dict[str, str], key: bytes, staff: set[str], found: dict[str, set[str]]) -> int:
    """Add one row's digests. Returns how many name pairs the row had, staff included."""
    pairs = {p for k, v in row.items() if k in FULL_NAME and (p := name_pair(v))}
    firsts = [v for k, v in row.items() if k in FIRST_NAME]
    lasts = [v for k, v in row.items() if k in LAST_NAME]
    for first in firsts:
        for last in lasts:
            a, b = name_words(first), name_words(last)
            if a and b and (p := pair_key(a[0], b[-1])):
                pairs.add(p)
    seen = len(pairs)
    pairs -= staff
    born = {d for k, v in row.items() if k in BIRTH_DATE for d in birth_dates(v)}
    found["pairs"].update(digest(key, p) for p in pairs)
    found["members"].update(digest(key, m) for k, v in row.items() if k in MEMBER_ID and (m := member_key(v)))
    found["name_dob"].update(digest(key, f"{p}|{d}") for p in pairs for d in born)
    return seen


def _staff_pairs(path: Path) -> set[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        raise RosterError("staff file could not be read") from None
    return {p for line in lines if (p := _staff_pair(line))}


def _staff_pair(line: str) -> str | None:
    """Like name_pair, after dropping titles and credentials: "Dr. Jane Smith, MD" is JANE|SMITH."""
    parts = [" ".join(w for w in name_words(part) if w not in CREDENTIALS) for part in line.split(",")]
    return name_pair(", ".join(part for part in parts if part))


def _write_atomic(target: Path, text: str) -> None:
    """Write beside the target, then rename, so a reader never sees half a file."""
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Roster:
    key: bytes
    pairs: frozenset[str]
    members: frozenset[str]
    name_dob: frozenset[str]

    def __repr__(self) -> str:
        return f"Roster(pairs={len(self.pairs)}, members={len(self.members)}, name_dob={len(self.name_dob)})"

    def check_line(self, text: str) -> list[str]:
        """Roster categories present on one line: name_pair, member_id, name_dob."""
        matched = set()
        # Hyphens stay inside words so double-barreled surnames match as stored.
        # A second pass splits on them for file names like first-last-labs.pdf.
        for variant in {text, text.replace("-", " ")}:
            tokens = [w for w in words(variant) if w not in LABELS and w not in SUFFIXES]
            for i, first in enumerate(tokens):
                # Pair each word with the next two, so a middle name can sit between.
                for second in tokens[i + 1:i + 3]:
                    p = pair_key(first, second)
                    if p and digest(self.key, p) in self.pairs:
                        matched.add(p)
        found = []
        if matched:
            found.append("name_pair")
        if any(m and digest(self.key, m) in self.members for m in map(member_key, member_candidates(text))):
            found.append("member_id")
        if matched and any(digest(self.key, f"{p}|{d}") in self.name_dob
                           for p in matched for d in birth_dates(text)):
            found.append("name_dob")
        return found


def load(roster_dir: Path, *, warn: bool = True) -> Roster:
    """Load and validate a roster. Any problem raises RosterError."""
    roster_dir = Path(roster_dir)
    key = read_key(roster_dir / KEY_FILE)
    try:
        payload = json.loads((roster_dir / ROSTER_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RosterError("roster file not found; run 'phi-guard build' first") from None
    except (OSError, ValueError):
        raise RosterError("roster file could not be read") from None
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
        raise RosterError("unsupported roster version")
    if not isinstance(payload.get("key_id"), str) or not hmac.compare_digest(payload["key_id"], key_id(key)):
        raise RosterError("roster was built with a different key")
    try:
        built_at = datetime.fromisoformat(payload["built_at"])
    except (KeyError, TypeError, ValueError):
        raise RosterError("roster timestamp is invalid") from None
    if built_at.tzinfo is None:
        raise RosterError("roster timestamp is invalid")
    sets = {}
    for name in DIGEST_FIELDS:
        values = payload.get(name)
        if not isinstance(values, list) or not all(isinstance(v, str) and HEX_DIGEST.fullmatch(v) for v in values):
            raise RosterError(f"roster field '{name}' is invalid")
        sets[name] = frozenset(values)
    if not sets["pairs"]:
        raise RosterError("roster has no name pairs")
    if warn and datetime.now(timezone.utc) - built_at > MAX_AGE:
        print("WARN: the PHI roster is more than 14 days old; rebuild it so new patients are covered.",
              file=sys.stderr)
    return Roster(key, sets["pairs"], sets["members"], sets["name_dob"])
