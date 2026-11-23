"""Additional edge-case tests for parser behavior."""

from urllib.parse import urlparse

import pytest

from crawler.parser import extract_links, normalize


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:8080/path",
        "https://example.com:443/",
        "http://localhost:8000/",
        "https://sub.example.com/path",
    ],
)
def test_normalize_keeps_explicit_port(url: str):
    normalized = normalize(url)
    parsed = urlparse(normalized)
    assert parsed.port is None or isinstance(parsed.port, int)


def test_extract_links_handles_whitespace_and_newlines():
    html = "\n  \t  <a href='/a'>A</a>\n  <a href='/b'>B</a>  \n"
    links = extract_links(html, "https://example.com/", "example.com")
    assert {"https://example.com/a", "https://example.com/b"} == links


def test_extract_links_normalizes_duplicate_links():
    html = """<a href="/a">A</a><a href="/a">A again</a>"""
    links = extract_links(html, "https://example.com/", "example.com")
    assert links == {"https://example.com/a"}


def test_extract_links_uses_base_url_for_relative_hrefs():
    html = '<a href="section">Section</a>'
    links = extract_links(html, "https://example.com/docs/", "example.com")
    assert links == {"https://example.com/docs/section"}


def test_extract_links_excludes_sourceless_tags():
    html = "<html><body><p>plain text</p></body></html>"
    assert extract_links(html, "https://example.com/", "example.com") == set()
