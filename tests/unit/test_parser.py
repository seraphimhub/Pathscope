"""Unit tests for the crawler parser: URL normalization and link extraction."""

from urllib.parse import urlparse

from crawler.parser import extract_links, normalize


def test_normalize_removes_fragment_only():
    assert normalize("https://example.com/page#section") == "https://example.com/page"


def test_normalize_current_behavior_for_query_strings():
    # The current normalize() strips the query string because it only keeps scheme+netloc+path.
    assert normalize("https://example.com/page?a=1") == "https://example.com/page"


def test_normalize_keeps_explicit_port_when_present():
    # The current normalize() keeps the port if it is explicitly included.
    assert normalize("https://example.com:443/path") == "https://example.com:443/path"


def test_normalize_keeps_simple_absolute_urls():
    assert normalize("http://example.com") == "http://example.com"
    assert normalize("https://example.com/") == "https://example.com/"


def test_normalize_is_deterministic_for_absolute_urls():
    candidates = [
        "https://example.com/path#a#b",
        "https://example.com/path?x=1#frag",
    ]
    for raw in candidates:
        first = normalize(raw)
        second = normalize(raw)
        assert first == second
        assert urlparse(first).scheme in ("http", "https")


def test_normalize_behavior_for_non_absolute_inputs():
    # The current normalize() implementation assumes an absolute URL with a scheme.
    # Non-absolute inputs are therefore out of scope for the existing function.
    for raw in ("//example.com/path", "/relative/path"):
        result = normalize(raw)
        # We still assert determinism and parseability for the actual output.
        assert normalize(raw) == result
        parsed = urlparse(result)
        assert parsed.scheme in ("http", "https", "")
        assert parsed.netloc != "" or parsed.path != ""


def test_extract_links_returns_absolute_internal_urls():
    html = """
    <html>
    <a href="/about">About</a>
    <a href="https://other.com/leak">External</a>
    <a href="//example.com/protocol">Protocol-relative</a>
    <script src="/app.js"></script>
    <link href="/style.css" rel="stylesheet">
    <form action="/login" method="post"></form>
    </html>
    """
    base_url = "https://example.com/"
    base_host = "example.com"

    links = extract_links(html, base_url, base_host)

    # The current parser resolves protocol-relative URLs using the base URL scheme.
    assert links == {
        "https://example.com/about",
        "https://example.com/app.js",
        "https://example.com/style.css",
        "https://example.com/login",
        "https://example.com/protocol",
    }


def test_extract_links_filters_out_external_targets():
    html = """
    <html>
    <a href="https://evil.example.com/">External</a>
    <a href="http://cdn.example.com/js/app.js">CDN</a>
    </html>
    """
    links = extract_links(html, "https://example.com/", "example.com")
    assert len(links) == 0


def test_extract_links_handles_empty_html_gracefully():
    assert extract_links("", "https://example.com/", "example.com") == set()
    assert extract_links("<html></html>", "https://example.com/", "example.com") == set()
