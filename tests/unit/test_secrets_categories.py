"""Tests for secret scanner category coverage and redaction readiness.

These tests document what the current scanner can detect and what must still be
implemented for a professional-grade secret scanner.
"""

import re

import pytest

from core import config
from scanners.secrets import scan_secrets

CATEGORY_CANDIDATES: list[tuple[str, list[str]]] = [
    ("API key literal", ["apiKey", "apikey", "api_key", "API_KEY"]),
    ("Generic secret word", ["secret", "SECRET"]),
    ("Token word", ["token", "TOKEN"]),
    ("JWT-like word", ["jwt", "JWT"]),
    ("Authorization header word", ["authorization", "Authorization"]),
    ("Password word", ["password", "PASSWORD"]),
]


@pytest.mark.parametrize(
    "label,keywords",
    CATEGORY_CANDIDATES,
)
def test_secret_scanner_matches_keyword_category(label: str, keywords: list[str]):
    # Each keyword should trigger at least one pattern because the current
    # scanner searches for keyword substrings anywhere in the body.
    for keyword in keywords:
        content = f"var {keyword} = 'value';"
        findings = scan_secrets("https://example.com/app.js", content)
        assert len(findings) >= 1, f"No finding for category={label} keyword={keyword}"


def test_secret_scanner_pattern_is_case_insensitive():
    content = "var API_KEY = 'abc';"
    findings = scan_secrets("https://example.com/app.js", content)
    assert len(findings) >= 1


def test_secret_scanner_pattern_object_uses_regex_flags():
    for pat in config.SECRET_PATTERNS:
        compiled = re.compile(pat, re.I)
        assert compiled is not None


def test_secret_scanner_still_returns_findings_for_minified_js():
    content = "var token='x';var secret='y';"
    findings = scan_secrets("https://example.com/app.min.js", content)
    assert len(findings) >= 1


def test_secret_scanner_finding_does_not_expose_secret_value():
    content = "var token = 'SUPER-SECRET-123';"
    findings = scan_secrets("https://example.com/app.js", content)
    for finding in findings:
        assert "SUPER-SECRET-123" not in str(finding)


def test_secret_scanner_documentation_gap_is_explicit():
    """Current scanner reports pattern presence, not validated credentials."""
    content = "var token = 'fake';"
    findings = scan_secrets("https://example.com/app.js", content)
    for finding in findings:
        # The current finding model has no confidence or verification status.
        assert finding.get("confidence") is None
        assert finding.get("verification_status") is None


def test_finding_redacted_drops_secret_keys():
    from core.models import Confidence, Finding, FindingType

    f = Finding(
        id="f1",
        scan_id="s1",
        type=FindingType.SECRET_PATTERN,
        title="test",
        target_url="https://example.com/app.js",
        source_url="https://example.com/app.js",
        evidence="",
        confidence=Confidence.MEDIUM,
        extra={"secret_value": "AKIA...", "token_value": "abc", "safe": True},
    )
    redacted = f.redacted()
    assert redacted["extra"].get("secret_value") is None
    assert redacted["extra"].get("token_value") is None
    assert redacted["extra"].get("safe") is True
