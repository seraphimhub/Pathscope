"""Tests for endpoint scanner categories, provenance, and verification status.

The current endpoint scanner extracts path literals and does not attempt to
verify whether the path is live. These tests document the current behavior and
the verification gap.
"""

import pytest

from scanners.endpoints import scan_endpoints

EXTRACTABLE_PATHS = [
    "/api/v1/users",
    "/api/v1/posts",
    "/health",
    "/admin/config",
    "/static/app.js",
]


@pytest.mark.parametrize("path", EXTRACTABLE_PATHS)
def test_endpoint_scanner_extracts_path_literals(path: str):
    content = f'fetch("{path}");'
    findings = scan_endpoints("https://example.com/app.js", content)
    assert any(f.get("endpoint") == path for f in findings)


def test_endpoint_scanner_extracts_multiple_paths():
    content = '"/api/v1/users" "/api/v1/posts" "/health"'
    findings = scan_endpoints("https://example.com/app.js", content)
    endpoints = {f.get("endpoint") for f in findings}
    assert endpoints >= {"/api/v1/users", "/api/v1/posts", "/health"}


def test_endpoint_scanner_reports_location_and_evidence():
    """Every finding must say where it came from and quote the literal."""
    content = 'var config = {};\nfetch("/api/v1/users");'
    findings = scan_endpoints("https://example.com/app.js", content)

    assert findings
    finding = findings[0]
    assert finding["evidence"] == "/api/v1/users"
    assert finding["url"] == "https://example.com/app.js"
    assert finding["line"] == 2
    assert finding["category"] == "path"
    # No request is made, so no provenance chain or verification is claimed.
    assert finding.get("provenance") is None
    assert finding.get("verification_status") is None


def test_endpoint_scanner_current_verification_status_is_unverified():
    """Current scanner does not verify whether the endpoint is live."""
    content = '"/api/v1/users"'
    findings = scan_endpoints("https://example.com/app.js", content)
    for finding in findings:
        assert finding.get("status") is None
        assert finding.get("verification_status") is None


def test_endpoint_scanner_does_not_extract_non_path_strings():
    content = '"not-a-path" "relative/no-leading-slash" "api/v1/users"'
    findings = scan_endpoints("https://example.com/app.js", content)
    endpoints = {f.get("endpoint") for f in findings}
    assert "/api/v1/users" not in endpoints
    assert "not-a-path" not in endpoints


def test_endpoint_scanner_is_stable_for_malformed_input():
    cases = ["", "var x = 1;", "'/api'", '"/api"']
    for content in cases:
        findings = scan_endpoints("https://example.com/app.js", content)
        assert isinstance(findings, list)
