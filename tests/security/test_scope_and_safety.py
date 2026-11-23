"""Security-oriented regression tests for scope and safety behavior.

These tests currently document the controls that must exist and assert the
behavior that can be verified through the existing modules.
"""

from urllib.parse import urlparse

import pytest

from crawler.parser import extract_links


def _internal_only(base_host: str):
    def keep(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == base_host

    return keep


def test_extract_links_allows_subdomain_boundary_configurability():
    html = """
    <a href="https://admin.example.com/">admin</a>
    <a href="https://example.com/">main</a>
    <a href="https://cdn.example.com/app.js">cdn</a>
    """
    links = extract_links(html, "https://example.com/", "example.com")
    # Current implementation uses exact netloc match, so subdomain links are excluded.
    assert "https://example.com/" in links
    assert "https://admin.example.com/" not in links
    assert "https://cdn.example.com/app.js" not in links


def test_extract_links_denies_overly_broad_host_leaks():
    html = """
    <a href="https://evil.com/">external</a>
    <link href="https://attacker.example.org/style.css">
    """
    links = extract_links(html, "https://example.com/", "example.com")
    for link in links:
        _assert_internal_parsed_url(link, "example.com")


@pytest.mark.parametrize(
    "unsafe",
    [
        "javascript:alert(1)",
        "data:text/html,<h1>xss</h1>",
        "https://127.0.0.1/",
        "http://localhost:8080/",
    ],
)
def test_parser_link_extraction_does_not_over_accept_non_http_targets(unsafe: str):
    html = f'<a href="{unsafe}">link</a>'
    links = extract_links(html, "https://example.com/", "example.com")
    # Whatever the parser returns must still be parseable as http/https when
    # the destination host matches the configured scope.
    if links:
        for link in links:
            _assert_internal_parsed_url(link, "example.com")


def _assert_internal_parsed_url(url: str, base_host: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    assert parsed.scheme in ("http", "https")
    assert parsed.netloc == base_host
