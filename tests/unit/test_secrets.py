"""Unit tests for the secret scanner.

The existing scanner is intentionally pattern- presence based and does not yet
implement confidence scoring or safe redaction. These tests describe and lock
the current behavior, and document the gap to be implemented next.
"""

import pytest

from scanners.secrets import scan_secrets


def test_scan_secrets_returns_dict_findings():
    findings = scan_secrets("https://example.com/config.js", "var token = 'x';")
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        assert finding.get("type") == "secret_pattern"
        assert finding.get("url") == "https://example.com/config.js"
        assert finding.get("pattern") is not None


def test_scan_secrets_reports_pattern_presence_not_secret_value():
    html = "var secret = 'super-secret-value';"
    findings = scan_secrets("https://example.com/app.js", html)
    patterns = {f["pattern"] for f in findings}
    assert "secret" in patterns
    # The scanner must not include the raw secret value in the finding.
    for f in findings:
        assert "super-secret-value" not in str(f)


def test_scan_secrets_is_case_insensitive_for_keywords():
    html = "var SECRET_TOKEN = 'abc';"
    findings = scan_secrets("https://example.com/app.js", html)
    # At minimum one keyword pattern should match in current impl.
    assert len(findings) >= 1


def test_scan_secrets_handles_empty_content_gracefully():
    findings = scan_secrets("https://example.com/", "")
    assert findings == []


def test_scan_secrets_handles_non_html_content_gracefully():
    findings = scan_secrets(
        "https://example.com/bundle.js",
        "function f(){ return apiKey; }",
    )
    assert len(findings) >= 1


def test_scan_secrets_does_not_crash_on_malformed_input():
    for content in (None,):
        with pytest.raises(TypeError):
            scan_secrets("https://example.com/", content)
