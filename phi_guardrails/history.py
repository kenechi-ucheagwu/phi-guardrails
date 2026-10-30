"""Scan every version of every file in a repository, plus every commit and tag message.

Deleting a file removes it from the working tree, not from history. Anyone who
clones the repository can still check out the old commit. Before a repository
goes public or moves to a new host, this scan reads every object reachable from
any ref, so an export deleted years ago still shows up.
"""
from __future__ import annotations

import html
import io
import re
import subprocess
import threading
import xml.etree.ElementTree as ElementTree
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterator

from . import __version__
from .errors import ScanError
from .precommit import GIT, allowlisted, binary_allowlist
from .scanner import PHI_OK, Scanner, decode_as, decode_text, text_lines, wide_encoding

IMAGE_EXT = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic"})
# Pictures inside an office file, besides anything in its media folders.
MEDIA_EXT = IMAGE_EXT | {".emf", ".wmf", ".svg", ".wdp", ".jxr"}
OFFICE_EXT = frozenset({".xlsx", ".xlsm", ".docx", ".pptx"})
MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_OFFICE_XML_BYTES = 64 * 1024 * 1024
MAX_LINES_LISTED = 50
# Office parts read as text: content, properties, relationships, legacy drawings.
XML_PARTS = (".xml", ".rels", ".vml")
# Office parts that are neither text nor pictures and hold nothing a person wrote.
_OFFICE_SKIP = re.compile(r"(?:^|/)(?:fonts|printerSettings)/", re.I)
_XML_DECLARATION = re.compile(r"\A\s*<\?xml[^>]*\?>")
_DECLARED_ENCODING = re.compile(rb"\A(?:\xef\xbb\xbf)?\s*<\?xml[^>]*?encoding\s*=\s*[\"']([A-Za-z0-9._-]+)")
_ATTRIBUTE = re.compile(r"""[\w:.-]+\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_MARKUP_DELIMITERS = re.compile(r"\A<(?:!--|\?)|(?:--|\?)>\Z")
# PDF objects as MuPDF prints them: names mostly decoded (/Im#61ge reads /Image),
# strings as (literal) or <hex>, dictionaries between << and >>.
_PDF_TOKEN = re.compile(r"<<|\(|<")
_PDF_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "\r": "", "\n": ""}
_PDF_OCTAL = re.compile(r"[0-7]{1,3}")
_PDF_NAME_ESCAPE = re.compile(r"#([0-9A-Fa-f]{2})")
_PDF_TEXT_BOMS = ((b"\xfe\xff", "utf-16-be"), (b"\xff\xfe", "utf-16-le"), (b"\xef\xbb\xbf", "utf-8"))
_PDF_METADATA = re.compile(r"/Type\s*/Metadata(?![A-Za-z0-9])")
_PDF_IMAGE = re.compile(r"/Subtype\s*/Image(?![A-Za-z0-9])")
# Objects that carry a file or media of their own: attachments in the document's
# list or in an annotation, sound, movies, rich media, 3D models.
_PDF_EMBEDDED = re.compile(r"/(?:EF|EmbeddedFile|FileAttachment|Sound|Movie|RichMedia|3D|3DD|Screen)(?![A-Za-z0-9])")
# Word and PowerPoint markup. Table cells end with a tab so a row's first and
# last name cells stay on one line; paragraphs, rows and breaks end a line.
_CELL_END = re.compile(r"</w:p>\s*</w:tc>|</a:p>\s*</a:txBody>")
_LINE_END = re.compile(r"</(?:w:p|w:tr|a:p|a:tr|comment)>|<(?:w:br|w:cr|a:br)\b[^>]*>")
_TAB = re.compile(r"<w:tab\b[^>]*>")
# A comment, a processing instruction, or a tag, whose quoted attribute values may hold ">".
_XML_TAG = re.compile(r"""<!--.*?-->|<\?.*?\?>|<(?:[^>"']|"[^"]*"|'[^']*')*>""", re.S)
_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)
_RAW_ENTRY = re.compile(r":\d{6} \d{6} ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) [A-Z]\d*")
_NULL_ID = re.compile(r"0+")


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, check=True).stdout


def _object_paths(repo: Path) -> dict[str, set[str]]:
    """Every object reachable from any ref, with every path it has had.

    rev-list names each object once, under the first path it meets, so a file
    renamed without changes would only show its new name. The raw log of
    every commit adds the other names: a patient-named file renamed to
    call-log.txt still turns up under its old name.
    """
    paths: dict[str, set[str]] = {}
    listing = _git(repo, "rev-list", "--objects", "--all").decode("utf-8", "surrogateescape")
    for line in listing.split("\n"):
        sha, _, path = line.partition(" ")
        if sha:
            paths.setdefault(sha, set()).update([path] if path else [])
    raw = _git(repo, "log", "--all", "-m", "--root", "--no-renames", "--no-abbrev", "--format=", "--raw", "-z")
    fields = raw.decode("utf-8", "surrogateescape").split("\0")
    for meta, path in zip(fields, fields[1:]):
        entry = _RAW_ENTRY.fullmatch(meta.lstrip("\n"))
        if entry and path:
            for sha in entry.groups():
                if not _NULL_ID.fullmatch(sha) and sha in paths:
                    paths[sha].add(path)
    return paths


def _read_objects(repo: Path, shas: list[str]) -> Iterator[tuple[str, str, bytes]]:
    """(id, type, content) for each object, read through one git cat-file process.

    A missing object comes back with type "missing". If git stops early or
    fails, the scan stops with an error, so a partial read never looks clean.
    """
    proc = subprocess.Popen([*GIT, "-C", str(repo), "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def feed() -> None:
        try:
            proc.stdin.write("".join(f"{sha}\n" for sha in shas).encode("ascii"))
            proc.stdin.close()
        except OSError:
            pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    finished = False
    try:
        for sha in shas:
            header = proc.stdout.readline().split()
            if len(header) == 2 and header[1] == b"missing":
                yield sha, "missing", b""
                continue
            if len(header) != 3:
                raise ScanError("git cat-file stopped early; the scan is incomplete")
            size = int(header[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            if len(data) != size:
                raise ScanError("git cat-file stopped early; the scan is incomplete")
            yield header[0].decode("ascii"), header[1].decode("ascii"), data
        finished = True
    finally:
        proc.stdout.close()
        code = proc.wait()
        writer.join()
    if finished and code != 0:
        raise ScanError("git cat-file failed; the scan is incomplete")


def _message(data: bytes) -> str | None:
    """The message of a commit or tag object, in the encoding its header names (UTF-8 by default)."""
    header, _, body = data.partition(b"\n\n")
    for line in header.split(b"\n"):
        if line.startswith(b"encoding "):
            text = decode_as(body, line[len(b"encoding "):].decode("ascii", "replace").strip())
            if text is not None:
                return text
            break
    return decode_text(body, lenient=True)


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _xml(data: bytes) -> str:
    """An office XML part as text, without its XML declaration.

    The encoding comes from a byte-order mark, the part's first bytes, or its
    declaration, and is UTF-8 otherwise. Decoding is strict: a part that isn't
    valid in its own encoding makes the file unreadable rather than half-read.
    Office files never declare a DTD, so one that does is refused rather than parsed.
    """
    codec = wide_encoding(data)
    if codec is None and data[:2] in (b"<\0", b"\0<"):
        codec = "utf-16-le" if data[0] else "utf-16-be"
    if codec is None:
        declared = _DECLARED_ENCODING.match(data)
        codec = declared.group(1).decode("ascii") if declared else "utf-8"
        # The declaration was just read as ASCII, so the encoding it names has to read ASCII the same way.
        if "<?xml".encode(codec) != b"<?xml":
            raise ValueError("office XML part declares an encoding its bytes don't use")
    text = data.decode(codec).lstrip("﻿")
    if "\0" in text:
        raise ValueError("office XML part has NUL characters")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("office XML part declares a DTD")
    return _XML_DECLARATION.sub("", text)


def _tag_values(tag: str) -> str:
    """What a tag holds besides markup: a comment's or processing instruction's text, or its attribute values."""
    if tag.startswith(("<!", "<?")):
        return _MARKUP_DELIMITERS.sub("", tag)
    values = (html.unescape(value) for pair in _ATTRIBUTE.findall(tag) for value in pair)
    return "\t".join(value for value in values if value.strip())


def _markup_text(xml: str) -> str:
    """Text of an office XML part, read twice: once with the tags removed, once with tags as spaces.

    Word, PowerPoint and Excel's rich text split a word across runs wherever
    its formatting or edit history changes, and keep real spaces inside the
    text, so the first reading joins "No" + "ra Vantly" back into one name.
    Charts, document properties and other parts put separate values side by
    side with nothing between them, so the second reading keeps them apart.
    It adds only the lines whose words it changes. Last come what the tags
    themselves hold, one line per distinct tag: attribute values such as link
    targets, sheet names, alt text and comment authors, and XML comments.
    CDATA sections count as ordinary text, so they join the text around them.
    """
    xml = _CDATA.sub(lambda section: html.escape(section.group(1), quote=False), xml)
    extra = list(dict.fromkeys(values for values in map(_tag_values, _XML_TAG.findall(xml)) if values))
    xml = _CELL_END.sub("\t", xml)
    xml = _LINE_END.sub("\n", _TAB.sub("\t", xml))
    joined = html.unescape(_XML_TAG.sub("", xml)).split("\n")
    spaced = html.unescape(_XML_TAG.sub(" ", xml)).split("\n")
    return "\n".join(joined + [s for j, s in zip(joined, spaced) if s.split() != j.split()] + extra)


def _string_item(item: ElementTree.Element) -> str:
    """Text of a shared or inline string: plain text and rich-text runs, not phonetic guides."""
    parts = []
    for child in item:
        name = _local(child.tag)
        if name == "t":
            parts.append(child.text or "")
        elif name == "r":
            parts.extend(t.text or "" for t in child if _local(t.tag) == "t")
    return "".join(parts)


def _cell_text(cell: ElementTree.Element, shared: list[str]) -> str:
    """A cell's value, plus its formula, which can hold text of its own (="Nora Vantly").

    A cell that points at a shared string the table doesn't have raises
    ValueError, so the workbook counts as unreadable instead of as blank.
    """
    kind = cell.get("t")
    formula = next((f.text or "" for f in cell if _local(f.tag) == "f"), "")
    if kind == "inlineStr":
        value = "".join(_string_item(item) for item in cell if _local(item.tag) == "is")
    else:
        value = next((v.text or "" for v in cell if _local(v.tag) == "v"), "")
        if kind == "s":
            index = int(value)
            if not 0 <= index < len(shared):
                raise ValueError("cell points past the shared string table")
            value = shared[index]
    return "\t".join(part for part in (value, formula) if part)


def _workbook_text(parts: dict[str, str]) -> str:
    """Every shared string, then one line per worksheet row with its cells separated by tabs.

    A workbook stores cell text in a shared table ordered by first use, so a
    row's first and last name are often far apart there. Rebuilding the rows
    puts them back together, the way a CSV export of the sheet would read.
    """
    shared: list[str] = []
    if "xl/sharedStrings.xml" in parts:
        root = ElementTree.fromstring(parts["xl/sharedStrings.xml"])
        shared = [_string_item(item) for item in root if _local(item.tag) == "si"]
    lines = list(shared)
    for name in sorted(n for n in parts if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        for _event, element in ElementTree.iterparse(io.BytesIO(parts[name].encode("utf-8"))):
            if _local(element.tag) == "row":
                cells = (_cell_text(cell, shared) for cell in element if _local(cell.tag) == "c")
                lines.append("\t".join(cell for cell in cells if cell))
                element.clear()
    return "\n".join(lines)


def _office_text(data: bytes) -> tuple[str | None, str | None]:
    """Text from every XML part of an .xlsx, .docx or .pptx file, and what in it nobody has read.

    The second value is "pictures" for media, "embedded files" for any other
    part that isn't XML (a workbook inside a document, an OLE object, macros,
    an imported web page), or None. Fonts, printer settings and empty parts
    don't count. Worksheets are also rebuilt row by row; see _workbook_text.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            unread = None
            for info in infos:
                name = info.filename.lower()
                if not info.file_size or name.endswith(XML_PARTS) or _OFFICE_SKIP.search(name):
                    continue
                if "/media/" in f"/{name}" or PurePosixPath(name).suffix in MEDIA_EXT:
                    unread = unread or "pictures"
                else:
                    unread = "embedded files"
            infos = sorted((info for info in infos if info.filename.lower().endswith(XML_PARTS)),
                           key=lambda i: i.filename)
            if sum(info.file_size for info in infos) > MAX_OFFICE_XML_BYTES:
                return None, unread
            parts = {info.filename: _xml(archive.read(info)) for info in infos}
            chunks = [_workbook_text(parts)] if any(name.startswith("xl/") for name in parts) else []
            chunks += [_markup_text(text) for text in parts.values()]
            # The archive's own part names and comment are in the file too.
            comment = decode_text(archive.comment, lenient=True)
            if comment is None:
                raise ValueError("office file has a binary archive comment")
            chunks += [info.filename for info in archive.infolist()] + [comment]
            return "\n".join(chunks), unread
    except (zipfile.BadZipFile, zlib.error, OSError, RuntimeError, LookupError, ValueError,
            ElementTree.ParseError):
        return None, None


def _pdf_string_text(data: bytes) -> str:
    """A PDF string as text: UTF-16 or UTF-8 when it starts with a byte-order mark, else UTF-8 or Latin-1.

    Latin-1 stands in for PDFDocEncoding, which matches it for letters. A
    string with a byte-order mark that doesn't decode makes the file unreadable.
    """
    for bom, codec in _PDF_TEXT_BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(codec)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _pdf_strings(source: str) -> tuple[str, list[str]]:
    """A PDF object's source with its strings blanked and its names decoded, and those strings as text."""
    outside: list[str] = []
    strings: list[str] = []
    position = 0
    while (token := _PDF_TOKEN.search(source, position)) is not None:
        outside.append(source[position:token.start()])
        position = token.end()
        if token.group() == "<<":
            outside.append("<<")
        elif token.group() == "<":
            close = source.index(">", position)
            digits = "".join(source[position:close].split())
            strings.append(_pdf_string_text(bytes.fromhex(digits + "0" * (len(digits) % 2))))
            outside.append(" ")
            position = close + 1
        else:
            raw, depth = [], 1
            while position < len(source):
                char = source[position]
                position += 1
                if char == "\\" and position < len(source):
                    octal = _PDF_OCTAL.match(source, position, position + 3)
                    if octal:
                        raw.append(chr(int(octal.group(), 8) & 0xFF))
                        position = octal.end()
                    else:
                        raw.append(_PDF_ESCAPES.get(source[position], source[position]))
                        position += 1
                    continue
                depth += {"(": 1, ")": -1}.get(char, 0)
                if not depth:
                    break
                raw.append(char)
            strings.append(_pdf_string_text("".join(raw).encode("latin-1", "replace")))
            outside.append(" ")
    outside.append(source[position:])
    return _PDF_NAME_ESCAPE.sub(lambda escape: chr(int(escape.group(1), 16)), "".join(outside)), strings


def _pdf_rows(items: list[tuple[float, float, float, str]]) -> list[str]:
    """Words, field values and notes regrouped into the rows a reader sees, each read left to right.

    MuPDF reads a page in blocks, so a first and a last name placed apart on
    one row, or typed into two form fields side by side, come out on separate
    lines. Each item is (top, bottom, left, text); an item joins the row its
    vertical middle falls inside.
    """
    rows: list[tuple[float, float, list[tuple[float, str]]]] = []
    for top, bottom, left, text in sorted(items, key=lambda item: ((item[0] + item[1]) / 2, item[2])):
        if rows and rows[-1][0] <= (top + bottom) / 2 <= rows[-1][1]:
            rows[-1][2].append((left, text))
        else:
            rows.append((top, bottom, [(left, text)]))
    return [" ".join(text for _left, text in sorted(row)) for _top, _bottom, row in rows]


def _pdf_text(data: bytes) -> tuple[str | None, str | None]:
    """Text from a PDF, and what in it nobody has read, when the optional PyMuPDF package is installed.

    The text covers the pages, including anything drawn outside the visible
    page, annotations, form fields, bookmarks, document properties and XMP
    metadata. Each page is also rebuilt row by row; see _pdf_rows. Every
    string and name in every object is added too, which
    covers the places a viewer shows that this list misses. The second value
    is "embedded files" for any object that carries a file or media of its
    own, attachment annotations included, or "pictures" for any image: one a
    page draws, inline ones included, and any image object in the file even
    if no page shows it. A PDF with no text is a scan, so it counts as pictures too.
    """
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError:
            return None, None
    try:
        with pymupdf.open(stream=data, filetype="pdf") as document:
            flags = pymupdf.TEXTFLAGS_TEXT & ~pymupdf.TEXT_MEDIABOX_CLIP
            pages = [page.get_text(flags=flags, clip=pymupdf.INFINITE_RECT()) for page in document]
            chunks = pages + [value for value in (document.metadata or {}).values() if isinstance(value, str)]
            chunks += [entry[1] for entry in document.get_toc()]
            pictures = not "".join(pages).strip()
            for page in document:
                annots, widgets = list(page.annots()), list(page.widgets())
                chunks += [annot.info.get(field, "") for annot in annots for field in ("title", "subject", "content")]
                chunks += [f"{widget.field_name or ''}\t{widget.field_value or ''}" for widget in widgets]
                items = [(word[1], word[3], word[0], word[4])
                         for word in page.get_text("words", flags=flags, clip=pymupdf.INFINITE_RECT())]
                items += [(widget.rect.y0, widget.rect.y1, widget.rect.x0, widget.field_value) for widget in widgets
                          if isinstance(widget.field_value, str) and widget.field_value.strip()]
                items += [(annot.rect.y0, annot.rect.y1, annot.rect.x0, annot.info.get("content", ""))
                          for annot in annots if annot.info.get("content", "").strip()]
                chunks += _pdf_rows(items)
                pictures = pictures or bool(page.get_image_info())
            objects = []
            for xref in range(1, document.xref_length()):
                source, strings = _pdf_strings(document.xref_object(xref, compressed=True))
                objects.append(source)
                chunks += [source, *strings]
                if _PDF_METADATA.search(source):
                    chunks.append(_markup_text(_xml(document.xref_stream(xref) or b"")))
            pictures = pictures or any(_PDF_IMAGE.search(source) for source in objects)
            text = "\n".join(chunks)
            if document.embfile_count() or any(_PDF_EMBEDDED.search(source) for source in objects):
                return text, "embedded files"
            return text, "pictures" if pictures else None
    except Exception:
        return None, None


def _extract(paths: list[str], data: bytes) -> tuple[str, str | None, str | None]:
    """The blob's kind, its text, and what it also holds that nobody has read ("pictures", "embedded files").

    Judged from every path the blob has had and its first bytes.
    """
    suffixes = {PurePosixPath(p).suffix.lower() for p in paths}
    if data.startswith(b"%PDF") or ".pdf" in suffixes:
        return ("pdf", *_pdf_text(data))
    if data.startswith(b"PK\x03\x04") and suffixes & OFFICE_EXT:
        return ("office", *_office_text(data))
    if suffixes & IMAGE_EXT:
        return "image", None, None
    if len(data) > MAX_TEXT_BYTES:
        return "too_large", None, None
    text = decode_text(data, lenient=True)
    return ("text", text, None) if text is not None else ("binary", None, None)


def _scan_lines(scanner: Scanner, text: str) -> tuple[Counter, list[int], int]:
    """Categories, line numbers, and how many hit lines carried a phi-ok marker."""
    categories: Counter = Counter()
    lines = []
    marked = 0
    for number, line in enumerate(text_lines(text), 1):
        hits = scanner.check_line(line, honor_phi_ok=False)
        if not hits:
            continue
        if PHI_OK.search(line):
            marked += 1
            continue
        categories.update(hits)
        lines.append(number)
    return categories, lines, marked


def _message_finding(scanner: Scanner, report: dict, kind: str, sha: str, data: bytes) -> None:
    message = _message(data)
    if message is None:
        report["not_scanned"].append({"paths": [f"{kind} {sha[:12]}"], "kind": f"{kind} message", "bytes": len(data)})
        return
    categories, lines, marked = _scan_lines(scanner, message)
    report["phi_ok_lines"] += marked
    if categories:
        report[f"{kind}_findings"].append({"object": sha[:12], "categories": dict(sorted(categories.items())),
                                           "lines": lines[:MAX_LINES_LISTED]})


def scan_history(repo: Path, scanner: Scanner) -> dict:
    """Build a JSON-ready report. It holds masked paths, categories and line numbers only."""
    repo = Path(repo)
    if _git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ScanError("this is a shallow clone, so part of the history is missing; fetch all of it first "
                        "(git fetch --unshallow, or fetch-depth: 0 in GitHub Actions)")
    # A bare or mirror clone has no work tree, so its git folder names the report.
    bare = _git(repo, "rev-parse", "--is-bare-repository").strip() == b"true"
    where = _git(repo, "rev-parse", "--absolute-git-dir" if bare else "--show-toplevel")
    toplevel = where.decode("utf-8", "replace").strip()
    objects = _object_paths(repo)
    allowed = binary_allowlist(repo, "HEAD")
    report = {
        "tool": "phi-guardrails",
        "version": __version__,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo": scanner.display_path(PurePosixPath(toplevel).name),
        "roster": "loaded" if scanner.roster is not None else "none",
        "blobs": 0,
        "commits": 0,
        "tags": 0,
        "findings": [],
        "path_findings": [],
        "ref_findings": [],
        "commit_findings": [],
        "tag_findings": [],
        "images_to_review": [],
        "not_scanned": [],
        "allowlisted": [],
        "phi_ok_lines": 0,
    }
    for path in sorted({p for ps in objects.values() for p in ps}):
        if scanner.path_hit(path):
            report["path_findings"].append(scanner.display_path(path))
    refs = _git(repo, "for-each-ref", "--format=%(refname)").decode("utf-8", "surrogateescape").split("\n")
    report["ref_findings"] = [scanner.display_path(ref) for ref in refs if ref and scanner.path_hit(ref)]
    for sha, kind, data in _read_objects(repo, list(objects)):
        paths = sorted(objects[sha])
        shown = [scanner.display_path(p) for p in paths]
        if kind == "missing":
            report["not_scanned"].append({"paths": shown, "kind": "missing", "bytes": 0})
            continue
        if kind in ("commit", "tag"):
            report[f"{kind}s"] += 1
            _message_finding(scanner, report, kind, sha, data)
            continue
        if kind != "blob":
            continue
        report["blobs"] += 1
        kind, text, unread = _extract(paths, data)
        if text is None or unread:
            entry = {"paths": shown, "kind": kind if text is None else f"{kind} with {unread}", "bytes": len(data)}
            if allowlisted(paths, allowed):
                report["allowlisted"].append(entry)
            elif kind == "image" or unread == "pictures":
                report["images_to_review"].append(entry)
            else:
                report["not_scanned"].append(entry)
        if text is None:
            continue
        categories, lines, marked = _scan_lines(scanner, text)
        report["phi_ok_lines"] += marked
        if categories:
            report["findings"].append({"paths": shown, "kind": kind, "categories": dict(sorted(categories.items())),
                                       "lines": lines[:MAX_LINES_LISTED]})
    report["summary"] = summarize(report)
    return report


def summarize(report: dict) -> dict[str, int]:
    def files_with(prefix: str) -> int:
        return sum(any(c.startswith(prefix) for c in f["categories"]) for f in report["findings"])

    return {
        "files_with_roster_hits": files_with("roster."),
        "files_with_secret_hits": files_with("secret."),
        "files_with_pattern_hits": files_with("pattern."),
        "paths_naming_patients": len(report["path_findings"]),
        "refs_naming_patients": len(report["ref_findings"]),
        "commit_messages_flagged": len(report["commit_findings"]),
        "tag_messages_flagged": len(report["tag_findings"]),
        "images_to_review": len(report["images_to_review"]),
        "not_scanned": len(report["not_scanned"]),
        "binaries_allowlisted": len(report["allowlisted"]),
        "lines_marked_phi_ok": report["phi_ok_lines"],
    }


def status(report: dict) -> str:
    """"findings", "review" (files nobody machine-checked and nobody allowlisted) or "clean"."""
    if any(report[key] for key in ("findings", "path_findings", "ref_findings", "commit_findings", "tag_findings")):
        return "findings"
    if report["images_to_review"] or report["not_scanned"]:
        return "review"
    return "clean"


def is_clean(report: dict) -> bool:
    return status(report) == "clean"


RESULTS = {
    "clean": "Result: clean",
    "review": "Result: needs review; look at the files above that could not be read, then list the safe ones "
              "in .phi-binary-allow",
    "findings": "Result: findings; fix them before this repository goes public",
}


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def format_summary(report: dict) -> str:
    lines = [f"Scanned {_count(report['blobs'], 'file version')}, {_count(report['commits'], 'commit message')} "
             f"and {_count(report['tags'], 'tag message')} (roster: {report['roster']})."]
    for finding in report["findings"]:
        categories = ", ".join(f"{c} x{n}" for c, n in finding["categories"].items())
        lines.append(f"  {' | '.join(finding['paths'])} [{finding['kind']}] "
                     f"lines {_short(finding['lines'])}: {categories}")
    lines += [f"  {path}: roster.path" for path in report["path_findings"]]
    lines += [f"  {ref}: roster.ref" for ref in report["ref_findings"]]
    for key, label in (("commit_findings", "commit"), ("tag_findings", "tag")):
        lines += [f"  {label} {item['object']} message: {', '.join(item['categories'])}" for item in report[key]]
    for key, label in (("images_to_review", "review by eye"), ("not_scanned", "could not read")):
        for item in report[key][:20]:
            lines.append(f"  {label}: {' | '.join(item['paths']) or '(no path)'} [{item['kind']}]")
        if len(report[key]) > 20:
            lines.append(f"  ({len(report[key]) - 20} more in the --json report)")
    width = max(len(name) for name in report["summary"])
    lines += [f"{name.replace('_', ' ').capitalize():<{width}}  {count}" for name, count in report["summary"].items()]
    lines.append(RESULTS[status(report)])
    return "\n".join(lines)


def _short(numbers: list[int]) -> str:
    shown = ", ".join(map(str, numbers[:8]))
    return shown + (", ..." if len(numbers) > 8 else "")
