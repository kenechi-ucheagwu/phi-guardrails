"""Pattern and secret detectors.

Positive examples are assembled at runtime with join() so this file does not
itself contain the shapes it tests. Otherwise the repository's own history
scan, which CI runs, would flag its tests.
"""
from __future__ import annotations

import pytest

from phi_guardrails import patterns


def join(*parts: str) -> str:
    return "".join(parts)


PHI_CASES = [
    ("ssn_shape", join("patient ss", "n: ", "123-45", "-6789"), "ssn: XXX-XX-XXXX"),
    ("dob_field", join("do", "b: ", "1961-03-14"), "dob: YYYY-MM-DD"),
    ("dob_field", join("\"date_of_", "birth\": \"", "07/30/1988\""), "date_of_birth is optional"),
    ("long_record_id", join("claim ", "1234567", "890123456"), "order 12345 shipped"),
    ("mrn_field", join("MR", "N# ", "00", "48213"), "MRN: <mrn>"),
    ("diagnosis_near_patient", join("patient seen for ", "E11", ".9"), join("E11", ".9 is the code for diabetes")),
    ("diagnosis_near_patient", join("S72", ".001A", " noted for pt"), "patient portal v2.10 release"),
    ("diagnosis_near_patient", join("pt tested positive, ", "U07", ".1"), join("U07", ".1 is the COVID-19 code")),
]


@pytest.mark.parametrize("category, positive, negative", PHI_CASES)
def test_phi_patterns(category, positive, negative):
    assert category in patterns.phi_hits(positive)
    assert category not in patterns.phi_hits(negative)


SECRET_CASES = [
    ("private_key", join("-----BEGIN ", "RSA PRIVATE KEY-----"), "-----BEGIN PUBLIC KEY-----"),
    ("github_token", join("gh", "p_", "Zr8Kq2Lm" * 5), "ghp_" + "x" * 36),
    ("sk_api_key", join("s", "k-ant-", "Q1w2E3r4" * 4), "sk-your-key-goes-here-please"),
    ("aws_access_key", join("AK", "IA", "Q7" * 8), "AKIA" + "X" * 16),
    ("google_api_key", join("AI", "za", "Ab1_" * 9), "AIza" + "x" * 35),
    ("google_oauth_secret", join("GOC", "SPX-", "k9Lm" * 6), "GOCSPX-<client-secret-here>"),
    ("oauth_token_json", join("{\"refresh_", "token\": \"", "1//0g" + "Zq9" * 8, "\"}"),
     "{\"refresh_token\": \"<refresh token>\"}"),
    ("client_secret", join("client_", "secret = '", "s3cr" * 4, "'"), "client_secret = 'your_client_secret'"),
    ("password_literal", join("pass", "word = '", "hunter22x", "'"), "password = 'changeme'"),
    ("api_key_literal", join("api_", "key = '", "Zx81" * 5, "'"), "api_key = 'your_api_key_value_here'"),
]


@pytest.mark.parametrize("category, positive, placeholder", SECRET_CASES)
def test_secret_patterns_skip_placeholders(category, positive, placeholder):
    assert category in patterns.secret_hits(positive)
    assert category not in patterns.secret_hits(placeholder)


def test_ordinary_code_is_quiet():
    lines = [
        "def risk_assessment(task_list):",
        "    timeout_ms = 1700000000000",
        "    return {'status': 'ok', 'version': '2.1.0'}",
    ]
    for line in lines:
        assert patterns.phi_hits(line) == []
        assert patterns.secret_hits(line) == []
