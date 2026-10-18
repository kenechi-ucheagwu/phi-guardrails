# phi-guardrails

Git hooks and a full-history scan that keep patient identifiers out of a code repository, without the guard itself holding a readable patient list.

Every name, date of birth and ID in this repository is synthetic.

## The problem

Automation in a medical office gets written under deadline pressure. A script fixes one stuck claim, a test reproduces one patient's bug, a CSV export lands next to the code "for a minute". Patient names, birth dates and member IDs end up in source files and commit messages.

Deleting the file later doesn't remove it. Git keeps every version, so anyone who can clone the repository can check out the old commit. A private repository still lives on someone else's servers, and if it is ever made public, its whole history goes with it.

Secret scanners don't catch this. A patient name is not a high-entropy string, and "Smith" appears in plenty of harmless code. The only reliable way to know a name belongs to a patient is to compare it with the real patient list. Copying that list into a scanner's config would create the very leak you were trying to prevent.

## How it works

```
patient CSV exports --+
staff names ----------+-- phi-guard build --> roster.v1.json (HMAC digests only)
32-byte key ----------+                              |
                                                     +--> pre-commit, pre-merge-commit  (lines being added, staged binaries)
                                                     +--> commit-msg                    (the message)
                                                     +--> scan-history                  (all of history)
```

1. `build` reads CSV exports and recognizes the usual EHR, billing and eligibility headers for names, birth dates and member IDs (`Patient Name`, `first_name`, `PatientLastName`, `Subscriber ID`, `DOB` and so on). Each name becomes an uppercase first+last pair with accents and suffixes like Jr removed. It stores HMAC-SHA256 digests of the name pairs, the member IDs, and each name+DOB combination. Staff names, with their titles and credentials stripped, are left out so a clinician's name in a commit isn't treated as a patient's. A CSV with no column it recognizes stops the build instead of quietly adding nobody.
2. At check time every word on a line is paired with the next two words, after dropping field labels such as `first_name`. So "Nora Jean Vantly", "Vantly, Nora" and `first_name="Nora", last_name="Vantly"` all match the same stored pair. Each pair is hashed with the same key and looked up. Member-ID-shaped tokens (with or without hyphens) and dates go through the same process.
3. Pattern checks cover what a roster can't know: an SSN next to the word "ssn", DOB and MRN fields, 15 to 17 digit record numbers, an ICD-10 code near the word "patient", and common credential formats (cloud keys, OAuth secrets, tokens, password literals).
4. Findings carry a path, a line number when there is one, and a category. The matched text is never printed, logged or put into an exception message. A file path or branch name that itself names a patient prints as a short keyed hash.

## Quick start

```bash
git clone https://github.com/DaDabbler/phi-guardrails
cd phi-guardrails
python -m pip install -e .

# The roster folder lives outside every repository.
export PHI_ROSTER_DIR=/secure/phi-roster
phi-guard init-key
phi-guard build /secure/exports --staff /secure/staff.txt

# In the repository you want to protect:
phi-guard install-hooks
phi-guard scan-history .
```

A blocked commit looks like this (synthetic data):

```
$ git commit -m "Retry stuck eligibility checks"
BLOCKED scripts/retry_eligibility.py:14 roster.name_pair
BLOCKED scripts/retry_eligibility.py:14 roster.name_dob
BLOCKED exports/denials.xlsx binary.not_allowlisted
phi-guardrails stopped this commit (3 findings). Remove the data, or end a line that is a reviewed false positive with '# phi-ok: <reason>'.
```

And a history scan before a repository goes public:

```
$ phi-guard scan-history . --json ../phi-report.json
Scanned 412 file versions, 96 commit messages and 3 tag messages (roster: loaded).
  scripts/old_fix.py [text] lines 8: roster.name_pair x1
  <masked:5be0c41a9e27>: roster.path
  commit 3f9c2a7b1d04 message: roster.name_pair
  review by eye: docs/screenshot.png [image]
Files with roster hits   1
Files with secret hits   0
Files with pattern hits  0
Paths naming patients    1
Refs naming patients     0
Commit messages flagged  1
Tag messages flagged     0
Images to review         1
Not scanned              0
Binaries allowlisted     2
Lines marked phi ok      0
Result: findings; fix them before this repository goes public
```

| Command | What it does |
|---|---|
| `init-key` | Create the 32-byte roster key. Never overwrites an existing key. |
| `build CSV...` | Hash names, member IDs and DOBs from CSV files or folders. `--staff` leaves staff out; `--merge` keeps what the roster already has; `--allow-empty` skips CSVs with no name columns instead of stopping. |
| `check FILE...` | Check whole files on disk. |
| `install-hooks` | Install `pre-commit`, `pre-merge-commit` and `commit-msg` hooks that run with this Python interpreter. |
| `pre-commit`, `commit-msg FILE` | What the hooks run. |
| `scan-history [REPO]` | Scan every blob reachable from any ref under every path it has had, every commit and tag message, and every ref name. `--json OUT` writes the full report. |

Every command that reads the roster takes `--roster-dir` (or reads `PHI_ROSTER_DIR`), and `--no-roster` runs only the pattern and secret checks. Exit codes: 0 clean, 1 findings, files needing review, or a blocked commit, 2 usage or setup error.

## Design choices

- **Keyed hashes, not a list.** Plain SHA-256 digests of names can be reversed by hashing a dictionary of common names. HMAC digests can't be tested against a guess without the key, so a copy of `roster.v1.json` on its own doesn't reveal who is on it. Masked paths in reports use the same key. The roster stores a fingerprint of its key and refuses to load with the wrong one.
- **Values never leave the process.** Findings have no field for matched text. Exception messages never include scanned content. A build error masks the path of an export that names a patient this build found or the existing roster already knows; a first build can't recognize a name it has never seen, so keep export file names plain. An unexpected error prints a generic line, because exception text can quote file contents. `PHI_GUARD_DEBUG=1` prints the full traceback instead; use it only with synthetic data.
- **Fail closed.** A missing roster, a damaged roster, an unreadable commit message or an internal error blocks the commit. `--no-roster` is an explicit choice, and it says so on every run. In a history scan, a file nobody could read, such as a workbook whose cells point at strings it doesn't have, counts against a clean result until someone looks at it and lists it in `.phi-binary-allow`. A shallow clone, or a git read that stops early, ends the scan with an error instead of a partial "clean". Both the hooks and the scan read objects as stored, ignoring `git replace` refs that could stand a clean commit in for the real one.
- **Binaries are blocked by default.** Spreadsheets, PDFs and screenshots are where patient data usually hides, and a text scanner can't read them. Known-safe files go in `.phi-binary-allow`, one glob per line, reviewed like any other change. The history scan does read Word, Excel and PowerPoint files: the text, attribute values and comments of every XML part, in whatever encoding it uses (cells row by row with their formulas, sheet names, links, alt text, charts, document properties), and the names of the parts themselves. It reads PDFs too when the `pdf` extra is installed: page text, including any drawn outside the visible page and with each page also rebuilt row by row, notes, form fields, bookmarks, properties, XMP metadata, and every string and name in the file's objects. Documents with pictures inside, and PDFs with images or no text layer, still go on the list to review by eye. A part it can't decode, a file embedded in another one, an attachment, or a macro project counts as unread.
- **Commits check only the lines they add.** A repository with old problems can still take new commits. `scan-history` is how you find the old problems.
- **The commit-msg hook goes by what git says it will drop.** Hooks can't see `git commit --cleanup`, but git's editor template spells it out. The template's file list is skipped only after git's hint that comment lines "will be ignored", and the `commit -v` diff only below a cut line that comes after that hint (or, in the scissors mode, below the first cut line, where git always cuts). So the commit that deletes a patient file isn't blocked for naming it in that list. Every other line is checked, comments included, and so is all of a message from `-m` or `-F`, or one git says it will keep verbatim.
- **The roster lives outside the repository.** `.gitignore` here ignores `*.key` and `roster*/` as a second line of defense, and the roster warns when it is more than 14 days old so new patients get covered. `--merge` rebuilds keep earlier digests, so deleting an old export never shrinks coverage.
- **Standard library only.** PDF text extraction is optional (`python -m pip install -e ".[pdf]"`).

## Limits

- The roster only knows patients from the exports it was built from. Someone added after the last build, or from a system you didn't export, is invisible to it. The pattern checks help, but they are heuristics and will sometimes fire on harmless text.
- Names match as first+last pairs within three words on one line of extracted text: a row of a CSV, a workbook or a PDF page, or a line of a document. A first and last name in separate paragraphs, or in form fields on different rows, won't match. A first name on its own, initials, a misspelling, or a name in a non-Latin script won't match.
- Images are listed for a person to look at; there is no OCR. PDF text drawn with a font that doesn't map back to letters, or inside a drawing no page uses, isn't read either.
- Spreadsheets store dates as day counts, so a birth date in an `.xlsx` cell doesn't count toward a name+DOB match. The name pair on the same row still matches.
- The hooks are there to catch mistakes, not someone set on getting data past them. They run on the developer's machine. `git commit --no-verify` skips them, and so do rebases and cherry-picks. Files stored in Git LFS are pointers, so their contents aren't checked. Run `scan-history` in CI and before any repository changes visibility or hosts.
- The commit-msg hook reads git's editor template in English. With git set to another language it checks every line, so a commit that deletes a patient-named file needs `-m` to get through. It also checks the `commit -v` diff when an editor saved the message with CRLF line endings, because Linux git keeps that diff in the commit. A message that copies git's template text word for word can get lines past the hook: tab-indented comment lines after a copied "will be ignored" hint, or lines below copied cut lines placed after it.
- `.phi-binary-allow` matches paths, not contents. A file saved later under an allowlisted pattern is exempt too, so keep the patterns narrow.
- This is a guardrail for developers. It is not a HIPAA compliance program, a risk assessment, or a substitute for a business associate agreement with whoever hosts your code.

## Where it came from

I run IT operations at a primary-care practice and write its automation in Python: EHR claim workflows, eligibility checks, payer portal reports. I'm also a nursing student. This is a standalone, tested version of the gate that guards that codebase. None of the practice's data is here; the tests build their roster from invented people at runtime.

## What's next

- A name-recognition pass (spaCy or Presidio) that flags person names missing from the roster, for review rather than blocking.
- OCR for images in the history scan.
- A server-side pre-receive hook, so `--no-verify` and rebases can't skip the check.
- A packaged GitHub Action that runs `scan-history --no-roster` on pull requests. This repository's own CI already does it for itself.

## Development

```bash
python -m pip install -e ".[dev,pdf]"
python -m pytest
```

The tests create temporary git repositories, isolated from your git config and from any repository above the test folder. Without the `pdf` extra, the PDF tests are skipped. Test data is assembled at runtime, and one test runs the full roster check over every file in this repository, so it passes its own scan.

## License

MIT
