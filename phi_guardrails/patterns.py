"""Value-free heuristics that work alongside the roster.

The roster only knows patients that were in its exports. These checks look for
shapes instead: an SSN next to the word "ssn", a DOB field, a 15-17 digit
record number, an ICD-10 code near the word "patient", and common credential
formats. They return category names only, and they will sometimes fire on
harmless text. Mark a reviewed line with "# phi-ok: <reason>".
"""
from __future__ import annotations

import re

_DATE = r"(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})"
# ICD-10-CM shape with the dot (E11.9, S72.001A, U07.1). Case-sensitive on purpose.
_ICD10 = r"\b[A-Z]\d[0-9A-Z]\.[0-9A-Z]{1,4}\b"
_PATIENT_WORD = r"(?i:\b(?:patient|pt|member)\b)"

PHI_PATTERNS = {
    "ssn_shape": re.compile(
        r"\b(?:ssn|social)\b.{0,20}\b\d{3}-\d{2}-\d{4}\b|\b\d{3}-\d{2}-\d{4}\b.{0,20}\bssn\b", re.I),
    "dob_field": re.compile(
        rf"\b(?:dob|date[ _]of[ _]birth|birth[ _]?date)\b[\"']?\s*[:=,]?\s*[\"']?{_DATE}", re.I),
    "long_record_id": re.compile(r"(?<![0-9A-Za-z.])\d{15,17}(?![0-9A-Za-z.])"),
    "mrn_field": re.compile(
        r"\b(?:mrn|medical[ _]record[ _](?:number|num|no))\b[\"']?\s*[:=#]?\s*[\"']?[A-Z0-9-]*\d{5,}", re.I),
    "diagnosis_near_patient": re.compile(rf"{_ICD10}.{{0,80}}{_PATIENT_WORD}|{_PATIENT_WORD}.{{0,80}}{_ICD10}"),
}

SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}"),
    "sk_api_key": re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{24,}"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),
    "google_oauth_secret": re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{20,}"),
    "oauth_token_json": re.compile(r"\"(?:refresh_token|access_token)\"\s*:\s*\"[^\"]{20,}\""),
    "client_secret": re.compile(r"client_secret[\"']?\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']", re.I),
    "password_literal": re.compile(
        r"\b(?:password|passwd|pwd)\b[\"']?\s*[:=]\s*[\"'][^\"'\s{}$%<>]{6,}[\"']", re.I),
    "api_key_literal": re.compile(
        r"\b(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\b[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-./+=]{16,}[\"']",
        re.I),
}

# Documentation and sample configs are full of these; they are not credentials.
PLACEHOLDER = re.compile(r"x{4,}|\*{4,}|your[_-]|example|placeholder|changeme|dummy|<[^>]+>|\.\.\.", re.I)


def phi_hits(line: str) -> list[str]:
    return [name for name, pattern in PHI_PATTERNS.items() if pattern.search(line)]


def secret_hits(line: str) -> list[str]:
    return [name for name, pattern in SECRET_PATTERNS.items()
            if any(not PLACEHOLDER.search(m.group()) for m in pattern.finditer(line))]
