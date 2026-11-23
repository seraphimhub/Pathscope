"""Unit tests for the endpoint scanner.

The current endpoint scanner extracts path-like literals from source content.
"""

from scanners.endpoints import scan_endpoints


def test_scan_endpoints_extracts_quoted_paths():
    findings = scan_endpoints(
        "https://example.com/app.js",
        'fetch("/api/v1/users");',
    )
    assert any(f.get("endpoint") == "/api/v1/users" for f in findings)


def test_scan_endpoints_returns_findings_with_urls():
    findings = scan_endpoints("https://example.com/app.js", '"/admin/config"')
    assert all(f.get("url") == "https://example.com/app.js" for f in findings)


def test_scan_endpoints_returns_no_findings_for_empty_content():
    assert scan_endpoints("https://example.com/app.js", "") == []


def test_scan_endpoints_extracts_multiple_paths():
    content = '"/api/v1/users" "/api/v1/posts" "/health"'
    findings = scan_endpoints("https://example.com/app.js", content)
    endpoints = {f.get("endpoint") for f in findings}
    assert endpoints >= {"/api/v1/users", "/api/v1/posts", "/health"}


def test_scan_endpoints_does_not_include_non_paths_by_default():
    content = '"/api/v1/users" "not-a-path" "relative/no-leading-slash"'
    findings = scan_endpoints("https://example.com/app.js", content)
    endpoints = {f.get("endpoint") for f in findings}
    assert "/api/v1/users" in endpoints
    # The current regex only captures strings starting with "/".
    assert "not-a-path" not in endpoints
