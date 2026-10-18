"""Full-history scans: deleted files, old secrets, messages, paths, refs and office files."""
from __future__ import annotations

import io
import json
import re
import sys
import zipfile

import pytest
from fakes import PATIENTS, assert_no_values, commit, git

from phi_guardrails import cli, history
from phi_guardrails.errors import ScanError
from phi_guardrails.scanner import Scanner

PNG = b"\x89PNG\r\n\x1a\n" + bytes(32)
SHEET_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
WORD_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
CHART_NS = 'xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"'
CORE_NS = ('xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
           'xmlns:dc="http://purl.org/dc/elements/1.1/"')


def make_zip(parts: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        for name, data in parts.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def sheet(rows: str, after: str = "") -> str:
    return f"<worksheet {SHEET_NS}><sheetData>{rows}</sheetData>{after}</worksheet>"


def document(body: str) -> str:
    return f"<w:document {WORD_NS}><w:body>{body}</w:body></w:document>"


def make_xlsx(rows: list[list[str]]) -> bytes:
    """A workbook stored the way Excel stores one: a shared string table in order of first use, and rows
    whose cells point into it."""
    shared: list[str] = []
    sheet_rows = []
    for number, row in enumerate(rows, 1):
        cells = []
        for column, value in enumerate(row):
            if value not in shared:
                shared.append(value)
            cells.append(f'<c r="{chr(65 + column)}{number}" t="s"><v>{shared.index(value)}</v></c>')
        sheet_rows.append(f'<row r="{number}">{"".join(cells)}</row>')
    strings = "".join(f"<si><t>{value}</t></si>" for value in shared)
    return make_zip({"xl/sharedStrings.xml": f'<sst {SHEET_NS} count="{len(shared)}">{strings}</sst>',
                     "xl/worksheets/sheet1.xml": sheet("".join(sheet_rows))})


def make_docx(body: str, *, picture: bool = False) -> bytes:
    parts = {"word/document.xml": document(body)}
    if picture:
        parts["word/media/image1.png"] = PNG
    return make_zip(parts)


def make_pdf(build) -> bytes:
    """A one-page PDF made with PyMuPDF; build(document, page) adds what the test needs."""
    pymupdf = pytest.importorskip("pymupdf")
    with pymupdf.open() as pdf:
        build(pdf, pdf.new_page())
        return pdf.tobytes()


def roster_hits(scanner, text: str) -> set[str]:
    return {category for _number, category in scanner.check_text(text) if category.startswith("roster.")}


def run(text: str) -> str:
    return f"<w:r><w:t xml:space=\"preserve\">{text}</w:t></w:r>"


def findings_for(report, path):
    return [f for f in report["findings"] if path in f["paths"]]


def test_finds_a_patient_file_deleted_from_head(repo, scanner):
    p = PATIENTS[2]
    commit(repo, {"exports/denials.csv": f"name,dob\n{p.last} {p.first},{p.dob}\n"}, "add export")
    git(repo, "rm", "-q", "exports/denials.csv")
    git(repo, "commit", "-q", "--no-verify", "-m", "remove export")
    assert not (repo / "exports" / "denials.csv").exists()

    report = history.scan_history(repo, scanner)
    [hit] = findings_for(report, "exports/denials.csv")
    assert hit["categories"] == {"roster.name_dob": 1, "roster.name_pair": 1}
    assert hit["lines"] == [2]
    assert report["summary"]["files_with_roster_hits"] == 1
    assert history.status(report) == "findings"
    assert_no_values(json.dumps(report))


def test_finds_a_secret_that_was_replaced(repo, scanner):
    token = "gh" + "p_" + "Zr8Kq2Lm" * 5
    commit(repo, {"config.py": f'TOKEN = "{token}"\n'}, "wire up the api")
    commit(repo, {"config.py": 'TOKEN = os.environ["TOKEN"]\n'}, "read the token from the environment")

    report = history.scan_history(repo, scanner)
    [hit] = findings_for(report, "config.py")
    assert hit["categories"] == {"secret.github_token": 1}
    assert token not in json.dumps(report)
    assert report["commits"] == 2


def test_flags_commit_messages_and_paths(repo, scanner):
    p = PATIENTS[0]
    commit(repo, {"README.md": "claims tools\n"}, f"fix claim for {p.full_name}")
    commit(repo, {f"notes/{p.first}-{p.last}.txt": "called back\n"}, "add notes")

    report = history.scan_history(repo, scanner)
    assert [c["categories"] for c in report["commit_findings"]] == [{"roster.name_pair": 1}]
    assert len(report["path_findings"]) == 1 and report["path_findings"][0].startswith("<masked:")
    dumped = json.dumps(report) + history.format_summary(report)
    assert_no_values(dumped)
    assert p.first not in dumped


def test_finds_a_patient_named_path_after_a_plain_rename(repo, scanner):
    # rev-list names each blob once, under its newest path, so the old name has to come from the log.
    p = PATIENTS[5]
    commit(repo, {f"notes/{p.last}_{p.first}.txt": "called back\n"}, "add notes")
    git(repo, "mv", f"notes/{p.last}_{p.first}.txt", "notes/call-log.txt")
    git(repo, "commit", "-q", "--no-verify", "-m", "rename notes")

    report = history.scan_history(repo, scanner)
    assert len(report["path_findings"]) == 1
    assert history.status(report) == "findings"
    assert_no_values(json.dumps(report))


def test_checks_tag_messages_and_branch_names(repo, scanner):
    p = PATIENTS[3]
    commit(repo, {"a.txt": "one\n"}, "first")
    git(repo, "tag", "-a", "v1", "-m", f"release for {p.full_name}")
    git(repo, "branch", f"fix/{p.first.lower()}-{p.last.lower()}-claim")

    report = history.scan_history(repo, scanner)
    assert report["tags"] == 1
    assert [t["categories"] for t in report["tag_findings"]] == [{"roster.name_pair": 1}]
    assert len(report["ref_findings"]) == 1 and report["ref_findings"][0].startswith("<masked:")
    dumped = json.dumps(report) + history.format_summary(report)
    assert_no_values(dumped)
    assert p.first.lower() not in dumped


def test_reads_spreadsheets_and_lists_images_and_pdfs(repo, scanner):
    p = PATIENTS[4]
    # The first name is used in an earlier row, so its shared string sits far from the surname's.
    rows = [["First", "Last", "DOB", "Balance"],
            [p.first, "Quill", "01/02/1950", "10"],
            ["Sam", "Ortolan", "03/04/1960", "0"],
            [p.first, p.last, p.dob_us, "25"]]
    commit(repo, {
        "reports/aging.xlsx": make_xlsx(rows),
        "docs/screenshot.png": PNG,
        "docs/form.pdf": b"%PDF-1.4 not a real document",
    }, "add reports")

    report = history.scan_history(repo, scanner)
    [hit] = findings_for(report, "reports/aging.xlsx")
    assert hit["kind"] == "office"
    assert {"roster.name_pair", "roster.name_dob"} <= set(hit["categories"])
    assert [i["paths"] for i in report["images_to_review"]] == [["docs/screenshot.png"]]
    assert [(n["paths"], n["kind"]) for n in report["not_scanned"]] == [(["docs/form.pdf"], "pdf")]


def test_reads_word_text_split_across_runs_and_table_cells(repo, scanner):
    # Word starts a new run wherever formatting or edit history changes, even inside a word.
    split, table = PATIENTS[0], PATIENTS[3]
    paragraph = f"<w:p>{run('Called ')}{run(split.first[:2])}{run(split.first[2:] + ' ' + split.last)}</w:p>"
    cells = "".join(f"<w:tc><w:p>{run(value)}</w:p></w:tc>" for value in (table.first, table.last))
    commit(repo, {"notes/split.docx": make_docx(paragraph),
                  "notes/table.docx": make_docx(f"<w:tbl><w:tr>{cells}</w:tr></w:tbl>")}, "add notes")

    report = history.scan_history(repo, scanner)
    for path in ("notes/split.docx", "notes/table.docx"):
        [hit] = findings_for(report, path)
        assert hit["categories"] == {"roster.name_pair": 1}
    assert_no_values(json.dumps(report))


def test_documents_with_pictures_need_review(repo, scanner):
    commit(repo, {"docs/letter.docx": make_docx(f"<w:p>{run('See the attached scan.')}</w:p>", picture=True)},
           "add letter")
    report = history.scan_history(repo, scanner)
    assert [(i["paths"], i["kind"]) for i in report["images_to_review"]] == [(["docs/letter.docx"],
                                                                               "office with pictures")]
    assert history.status(report) == "review"

    commit(repo, {".phi-binary-allow": "docs/letter.docx\n"}, "reviewed the letter by hand")
    assert history.is_clean(history.scan_history(repo, scanner))


def test_reads_spreadsheet_formulas_and_text_outside_cells(scanner):
    p = PATIENTS[2]
    formula = sheet(f'<row r="1"><c r="A1" t="str"><f>"{p.first} {p.last}"</f><v></v></c></row>')
    header = sheet("", f"<headerFooter><oddHeader>{p.full_name}</oddHeader></headerFooter>")
    # A chart caches its labels as separate values with no space between them.
    chart = (f'<c:chartSpace {CHART_NS}><c:pt idx="0"><c:v>{p.first}</c:v></c:pt>'
             f'<c:pt idx="1"><c:v>{p.last}</c:v></c:pt></c:chartSpace>')
    title = f"<cp:coreProperties {CORE_NS}><dc:title>{p.last}, {p.first}</dc:title></cp:coreProperties>"
    for path, parts in (("book.xlsx", {"xl/worksheets/sheet1.xml": formula}),
                        ("book.xlsx", {"xl/worksheets/sheet1.xml": header}),
                        ("book.xlsx", {"xl/worksheets/sheet1.xml": sheet(""), "xl/charts/chart1.xml": chart}),
                        ("letter.docx", {"word/document.xml": document(""), "docProps/core.xml": title})):
        kind, text, unread = history._extract([path], make_zip(parts))
        assert (kind, unread) == ("office", None)
        assert "roster.name_pair" in roster_hits(scanner, text), list(parts)


def test_reads_office_parts_in_any_encoding_and_what_their_tags_hold(scanner):
    p = PATIENTS[1]
    declared = '<?xml version="1.0" encoding="UTF-16"?>'
    body = document(f"<w:p>{run(p.full_name)}</w:p>")
    link = (f'<Relationships><Relationship Id="rId1" TargetMode="External" '
            f'Target="https://example.invalid/{p.first}_{p.last}"/></Relationships>')
    picture = document(f'<wp:docPr id="1" name="Picture 1" descr="Photo of {p.full_name}"/>')
    tab = f'<workbook {SHEET_NS}><sheets><sheet name="{p.last}, {p.first}" sheetId="1"/></sheets></workbook>'
    comment = document(f"<!-- {p.full_name} -->")
    # Attribute values may hold ">" and character references, and CDATA joins the text around it.
    angle = document(f'<w:bookmarkStart w:id="0" w:name="{p.first} > {p.last}"/>')
    references = document(f'<w:bookmarkStart w:id="0" w:name="{"".join(f"&#{ord(c)};" for c in p.full_name)}"/>')
    cdata = document(f"<w:p><w:r><w:t><![CDATA[{p.first[:2]}]]>{p.first[2:]} {p.last}</w:t></w:r></w:p>")
    for path, parts in (("letter.docx", {"word/document.xml": (declared + body).encode("utf-16")}),
                        ("letter.docx", {"word/document.xml": body.encode("utf-16-le")}),
                        ("letter.docx", {"word/document.xml": document(""), "word/_rels/document.xml.rels": link}),
                        ("letter.docx", {"word/document.xml": picture}),
                        ("book.xlsx", {"xl/workbook.xml": tab}),
                        ("letter.docx", {"word/document.xml": comment}),
                        ("letter.docx", {"word/document.xml": angle}),
                        ("letter.docx", {"word/document.xml": references}),
                        ("letter.docx", {"word/document.xml": cdata}),
                        ("letter.docx", {"word/document.xml": document(""),
                                         f"customXml/{p.last}_{p.first}.xml": "<a/>"})):
        kind, text, unread = history._extract([path], make_zip(parts))
        assert (kind, unread) == ("office", None)
        assert "roster.name_pair" in roster_hits(scanner, text), list(parts)
    # A value with no two letters in a row still counts, such as a member ID written with hyphens.
    member = document(f'<w:bookmarkStart w:id="0" w:name="{"-".join(p.member_id)}"/>')
    _kind, text, _unread = history._extract(["letter.docx"], make_zip({"word/document.xml": member}))
    assert "roster.member_id" in roster_hits(scanner, text)


def test_office_parts_that_dont_decode_cleanly_are_unreadable():
    body = document(f"<w:p>{run('Balance')}</w:p>")
    for data in (b"<w:document>\xff\xfe broken</w:document>",
                 ('<?xml version="1.0" encoding="UTF-16"?>' + body).encode("utf-8"),
                 ('<?xml version="1.0" encoding="no-such-codec"?>' + body).encode("utf-8"),
                 body.encode("utf-32-le")):
        assert history._extract(["letter.docx"], make_zip({"word/document.xml": data})) == ("office", None, None)


def test_a_workbook_pointing_past_its_shared_strings_is_unreadable(repo, scanner):
    strings = f"<sst {SHEET_NS}><si><t>Balance</t></si></sst>"
    for index in ("999", "-1", ""):
        workbook = make_zip({"xl/sharedStrings.xml": strings,
                             "xl/worksheets/sheet1.xml": sheet(f'<row r="1"><c r="A1" t="s"><v>{index}</v></c></row>')})
        assert history._extract(["book.xlsx"], workbook) == ("office", None, None), index
    commit(repo, {"reports/broken.xlsx": workbook}, "add workbook")
    report = history.scan_history(repo, scanner)
    assert [(n["paths"], n["kind"]) for n in report["not_scanned"]] == [(["reports/broken.xlsx"], "office")]


def test_files_embedded_in_documents_need_review(repo, scanner):
    commit(repo, {
        "docs/letter.docx": make_zip({"word/document.xml": document(f"<w:p>{run('See the table.')}</w:p>"),
                                      "word/embeddings/Microsoft_Excel_Worksheet.xlsx": make_xlsx([["Balance"]])}),
        "tools/macros.xlsm": make_zip({"xl/worksheets/sheet1.xml": sheet(""), "xl/vbaProject.bin": bytes(64)}),
    }, "add office files")
    report = history.scan_history(repo, scanner)
    assert sorted((n["paths"], n["kind"]) for n in report["not_scanned"]) == [
        (["docs/letter.docx"], "office with embedded files"), (["tools/macros.xlsm"], "office with embedded files")]
    assert history.status(report) == "review"

    # Any part that is neither XML nor a picture counts, such as a web page Word imported whole.
    text = document(f"<w:p>{run('See below.')}</w:p>")
    imported = make_zip({"word/document.xml": text, "word/afchunk.mht": b"MIME-Version: 1.0\r\n"})
    assert history._extract(["letter.docx"], imported)[2] == "embedded files"
    # Fonts, printer settings and empty signature markers hold nothing anyone typed.
    plain = make_zip({"word/document.xml": text, "word/fonts/font1.odttf": bytes(64),
                      "xl/printerSettings/printerSettings1.bin": bytes(64), "_xmlsignatures/origin.sigs": b""})
    assert history._extract(["letter.docx"], plain)[2] is None


def test_pdfs_with_images_attachments_or_no_text_need_review(repo, scanner):
    def page_text(pdf, page):
        page.insert_text((72, 72), "Discharge instructions")

    def inline_image(pdf, page):
        page_text(pdf, page)
        contents = page.get_contents()[0]
        pdf.update_stream(contents, pdf.xref_stream(contents)
                          + b"\nq 9 0 0 9 99 99 cm BI /W 1 /H 1 /CS /G /BPC 8 ID \xff EI Q")

    def unused_image_with_an_escaped_name(pdf, page):
        page_text(pdf, page)
        xref = pdf.get_new_xref()
        pdf.update_object(xref, "<< /Type /XObject /Subtype /Im#61ge /Width 1 /Height 1 "
                                "/ColorSpace /DeviceGray /BitsPerComponent 8 >>")
        pdf.update_stream(xref, b"\xff")

    def drawing_only(pdf, page):
        page.draw_rect((9, 9, 99, 99))

    def attachment(pdf, page):
        page_text(pdf, page)
        pdf.embfile_add("list.csv", b"visits\n3\n")

    def attachment_on_the_page(pdf, page):
        # A file attached through an annotation isn't in the document's list of attachments.
        page_text(pdf, page)
        page.add_file_annot((50, 50), b"visits\n3\n", "list.txt")

    expected = {page_text: None, inline_image: "pictures", unused_image_with_an_escaped_name: "pictures",
                drawing_only: "pictures", attachment: "embedded files", attachment_on_the_page: "embedded files"}
    for build, unread in expected.items():
        kind, text, found = history._extract(["form.pdf"], make_pdf(build))
        assert (kind, found) == ("pdf", unread), build.__name__
    assert "Discharge instructions" in history._extract(["form.pdf"], make_pdf(page_text))[1]

    commit(repo, {"docs/chart.pdf": make_pdf(inline_image), "docs/packet.pdf": make_pdf(attachment)}, "add pdfs")
    report = history.scan_history(repo, scanner)
    assert [(i["paths"], i["kind"]) for i in report["images_to_review"]] == [(["docs/chart.pdf"], "pdf with pictures")]
    assert [(n["paths"], n["kind"]) for n in report["not_scanned"]] == [(["docs/packet.pdf"],
                                                                         "pdf with embedded files")]


def test_reads_pdf_notes_form_fields_bookmarks_and_properties(scanner):
    pymupdf = pytest.importorskip("pymupdf")
    p = PATIENTS[3]

    def note(pdf, page):
        page.add_text_annot((50, 50), f"Called {p.full_name}")

    def form_field(pdf, page):
        widget = pymupdf.Widget()
        widget.field_name, widget.field_type = "patient", pymupdf.PDF_WIDGET_TYPE_TEXT
        widget.field_value, widget.rect = p.full_name, pymupdf.Rect(72, 100, 300, 120)
        page.add_widget(widget)

    def bookmark(pdf, page):
        pdf.set_toc([[1, f"{p.first} {p.last}", 1]])

    def title(pdf, page):
        pdf.set_metadata({"title": f"{p.last}, {p.first}"})

    def xmp(pdf, page):
        page.insert_text((72, 72), "Discharge instructions")
        pdf.set_xml_metadata('<x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:dc="http://purl.org/dc/elements/1.1/">'
                             f"<dc:description>{p.full_name}</dc:description></x:xmpmeta>")

    def below_the_page(pdf, page):
        page.insert_text((72, 72), "Discharge instructions")
        contents = page.get_contents()[0]
        pdf.update_stream(contents, pdf.xref_stream(contents)
                          + f"\nBT /helv 11 Tf 72 -300 Td ({p.full_name}) Tj ET".encode("ascii"))

    def in_any_object(pdf, page):
        # A string or name only some viewers show: a tooltip as UTF-16, a name with an escaped space.
        page.insert_text((72, 72), "Discharge instructions")
        tooltip = (b"\xfe\xff" + p.full_name.encode("utf-16-be")).hex()
        pdf.update_object(pdf.get_new_xref(), f"<< /TU <{tooltip}> >>")
        pdf.update_object(pdf.get_new_xref(), f"<< /D /{p.first}#20{p.last} >>")

    # A first and a last name on one row, far apart or in two form fields side by side.
    def side_by_side(pdf, page):
        page.insert_text((72, 120), f"First name: {p.first}")
        page.insert_text((300, 120), f"Last name: {p.last}")

    def two_fields(pdf, page):
        page.insert_text((72, 72), "Discharge instructions")
        for name, value, left in (("FirstName", p.first, 72), ("LastName", p.last, 300)):
            widget = pymupdf.Widget()
            widget.field_name, widget.field_type = name, pymupdf.PDF_WIDGET_TYPE_TEXT
            widget.field_value, widget.rect = value, pymupdf.Rect(left, 100, left + 150, 120)
            page.add_widget(widget)

    for build in (note, form_field, bookmark, title, xmp, below_the_page, in_any_object, side_by_side, two_fields):
        _kind, text, _unread = history._extract(["form.pdf"], make_pdf(build))
        assert "roster.name_pair" in roster_hits(scanner, text), build.__name__

    # A string that reads like an attachment's key is only text.
    def sound_title(pdf, page):
        page.insert_text((72, 72), "Discharge instructions")
        pdf.set_metadata({"title": "Notes /Sound"})

    assert history._extract(["form.pdf"], make_pdf(sound_title))[2] is None


def test_pdfs_need_review_without_pymupdf(monkeypatch):
    monkeypatch.setitem(sys.modules, "pymupdf", None)
    monkeypatch.setitem(sys.modules, "fitz", None)
    assert history._extract(["form.pdf"], b"%PDF-1.7 a document") == ("pdf", None, None)


def test_commit_messages_with_nul_bytes_or_an_unusable_encoding():
    header = b"tree " + b"0" * 40 + b"\nauthor A <a@example.com> 0 +0000\n"
    assert history._message(header + b"encoding UTF-8\n\nfix\0retry\n") is None
    # Read as UTF-16, plain text turns into characters no check matches, so the header is not trusted.
    message = f"call {PATIENTS[0].full_name}\n"
    message = message if len(message) % 2 == 0 else " " + message
    assert history._message(header + b"encoding UTF-16\n\n" + message.encode("ascii")) == message


def test_replace_refs_cannot_hide_old_commits(repo, scanner):
    p = PATIENTS[1]
    commit(repo, {"exports/list.csv": f"{p.full_name}\n"}, "add export")
    git(repo, "rm", "-q", "exports/list.csv")
    git(repo, "commit", "-q", "--no-verify", "-m", "remove export")
    # A local replacement that cuts the clean commit off from its parent hides the export from plain git.
    git(repo, "replace", "--graft", "HEAD")
    assert "add export" not in git(repo, "log", "--format=%s")

    report = history.scan_history(repo, scanner)
    assert report["summary"]["files_with_roster_hits"] == 1
    assert history.status(report) == "findings"


def test_message_text_cannot_pose_as_an_object_id(repo, scanner, tmp_path):
    p = PATIENTS[2]
    message = tmp_path / "message.txt"
    message.write_bytes(f"note\x1e{p.member_id}\x1f{p.full_name}\n".encode("utf-8"))
    commit(repo, {"a.txt": "one\n"}, "first")
    git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-F", str(message))

    report = history.scan_history(repo, scanner)
    assert report["commits"] == 2
    [flagged] = report["commit_findings"]
    assert re.fullmatch(r"[0-9a-f]{12}", flagged["object"])
    assert {"roster.name_pair", "roster.member_id"} <= set(flagged["categories"])
    assert_no_values(json.dumps(report) + history.format_summary(report))


def test_a_repository_folder_named_after_a_patient_is_masked(tmp_path, scanner):
    p = PATIENTS[0]
    folder = tmp_path / f"{p.first}-{p.last}-notes"
    folder.mkdir()
    git(folder, "init", "-q")
    commit(folder, {"a.txt": "one\n"}, "first")
    report = history.scan_history(folder, scanner)
    assert report["repo"].startswith("<masked:")
    assert_no_values(json.dumps(report))


def test_unreadable_files_need_review_until_allowlisted(repo, scanner):
    commit(repo, {"exports/archive.zip": b"PK\x05\x06" + bytes(18), "docs/logo.png": PNG}, "add files")
    report = history.scan_history(repo, scanner)
    assert history.status(report) == "review" and not history.is_clean(report)
    assert history.format_summary(report).splitlines()[-1].startswith("Result: needs review")

    commit(repo, {".phi-binary-allow": "# looked at by hand\ndocs/*.png\nexports/archive.zip\n"}, "allowlist")
    report = history.scan_history(repo, scanner)
    assert history.is_clean(report)
    assert report["summary"]["binaries_allowlisted"] == 2


def test_oversized_text_needs_review(repo, scanner, monkeypatch):
    monkeypatch.setattr(history, "MAX_TEXT_BYTES", 16)
    commit(repo, {"exports/big.csv": "visit_count\n" * 4}, "add a large export")
    report = history.scan_history(repo, scanner)
    assert [(n["paths"], n["kind"]) for n in report["not_scanned"]] == [(["exports/big.csv"], "too_large")]
    assert history.status(report) == "review"


def test_refuses_a_shallow_clone(repo, scanner, tmp_path):
    commit(repo, {"a.txt": "one\n"}, "first")
    commit(repo, {"a.txt": "two\n"}, "second")
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow))
    with pytest.raises(ScanError, match="shallow clone"):
        history.scan_history(shallow, scanner)


def test_phi_ok_lines_are_counted_not_hidden(repo, scanner):
    p = PATIENTS[3]
    commit(repo, {"docs.py": f'EXAMPLE = "{p.full_name}"  # phi-ok: synthetic example\n'}, "docs")
    report = history.scan_history(repo, scanner)
    assert history.is_clean(report)
    assert report["summary"]["lines_marked_phi_ok"] == 1


def test_clean_repository(repo, scanner):
    commit(repo, {"README.md": "# claims tools\n", "src/app.py": "print('ok')\n"}, "initial commit")
    report = history.scan_history(repo, scanner)
    assert history.is_clean(report)
    assert report["repo"] == "repo"
    assert history.format_summary(report).endswith("Result: clean")


def test_command_writes_a_value_free_report(repo, roster_dir, tmp_path, capsys):
    p = PATIENTS[1]
    commit(repo, {"old.py": f"WHO = '{p.full_name}'\n"}, "old script")
    out = tmp_path / "report.json"
    code = cli.main(["scan-history", str(repo), "--roster-dir", str(roster_dir), "--json", str(out)])
    printed = capsys.readouterr().out
    assert code == 1
    assert "old.py [text] lines 1: roster.name_pair x1" in printed
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["files_with_roster_hits"] == 1
    assert_no_values(printed + out.read_text(encoding="utf-8"))


def test_command_rejects_a_folder_that_is_not_a_repository(tmp_path, roster_dir, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    code = cli.main(["scan-history", str(plain), "--roster-dir", str(roster_dir)])
    assert code == 2
    assert "not a git repository" in capsys.readouterr().err


def test_patterns_only_mode_reports_no_roster(repo):
    commit(repo, {"a.txt": "hello\n"}, "start")
    report = history.scan_history(repo, Scanner(None))
    assert report["roster"] == "none" and history.is_clean(report)
