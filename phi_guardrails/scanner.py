"""Run the roster and the patterns over text, and report findings without values."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import patterns
from .roster import Roster, mask

# A reviewed false positive: "# phi-ok: <reason>" (or "//" for JS-style files).
# The reason is required, so a bare marker does not silence anything.
PHI_OK = re.compile(r"(?:#|//)\s*phi-ok:\s*\S")
# Byte-order marks of wide encodings, longest first: the UTF-32LE mark starts with the UTF-16LE one.
WIDE_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
             (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))


@dataclass(frozen=True)
class Finding:
    """Where a hit is and what kind it is. There is no field for the matched text."""

    path: str
    line: int | None
    category: str

    def __str__(self) -> str:
        where = self.path if self.line is None else f"{self.path}:{self.line}"
        return f"{where} {self.category}"


class Scanner:
    def __init__(self, roster: Roster | None) -> None:
        self.roster = roster

    def check_line(self, line: str, *, honor_phi_ok: bool = True) -> list[str]:
        if honor_phi_ok and PHI_OK.search(line):
            return []
        found = []
        if self.roster is not None:
            found += [f"roster.{c}" for c in self.roster.check_line(line)]
        found += [f"pattern.{c}" for c in patterns.phi_hits(line)]
        found += [f"secret.{c}" for c in patterns.secret_hits(line)]
        return found

    def check_text(self, text: str, *, honor_phi_ok: bool = True) -> list[tuple[int, str]]:
        return [(number, category)
                for number, line in enumerate(text_lines(text), 1)
                for category in self.check_line(line, honor_phi_ok=honor_phi_ok)]

    def path_hit(self, path: str) -> bool:
        """True when a file path itself contains a roster identifier (exports/Last_First.csv)."""
        return self.roster is not None and bool(self.roster.check_line(path))

    def display_path(self, path: str) -> str:
        """The path for output: masked with the roster key if it names a patient, control characters escaped."""
        if self.path_hit(path):
            return mask(self.roster.key, path)
        return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in path)


def wide_encoding(data: bytes) -> str | None:
    """The codec named by a UTF-16 or UTF-32 byte-order mark, if the data starts with one."""
    return next((codec for bom, codec in WIDE_BOMS if data.startswith(bom)), None)


def decode_text(data: bytes, *, lenient: bool = False) -> str | None:
    """Return the bytes as text, or None when they can't be scanned safely as text.

    UTF-16 and UTF-32 files with a byte-order mark are decoded; Windows
    PowerShell 5.1 and regedit write them by default. Other data with NUL bytes
    is treated as binary. In lenient mode (history scans) text that isn't UTF-8
    is read as Windows-1252, the usual encoding of older exports. Commits stay
    strict: what can't be read is blocked.
    """
    codec = wide_encoding(data)
    if codec:
        try:
            text = data.decode(codec)
        except UnicodeDecodeError:
            return None
        return None if "\0" in text else text
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace") if lenient else None


def decode_as(data: bytes, encoding: str) -> str | None:
    """The bytes in an encoding a commit names, or None when that encoding can't be trusted for them.

    git's commit encodings are ASCII-compatible. Reading plain text as one
    that isn't (UTF-16, say) would turn a name into characters no check
    matches, so such an encoding is refused. Text with NUL bytes is binary,
    as in decode_text.
    """
    try:
        if "Az09 \n".encode(encoding) != b"Az09 \n":
            return None
        text = data.decode(encoding)
    except (LookupError, UnicodeError):
        return None
    return None if "\0" in text else text


def text_lines(text: str) -> list[str]:
    """Split on LF and drop the CR of CRLF, so line numbers match git and editors."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
