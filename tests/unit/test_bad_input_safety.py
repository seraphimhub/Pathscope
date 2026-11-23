"""Safety tests for bad inputs across parser and scanners."""

import pytest

from crawler.parser import extract_links
from scanners.endpoints import scan_endpoints
from scanners.secrets import scan_secrets

BAD_HTML_INPUTS = [
    "",
    "<html>",
    "<html><body>",
    "<a href='/a'>A</a>",
    "<a href='/a'>A</a></body>",
    "<img src='/a'/>",
    "<script src='/a'></script>",
    "<link href='/a'>",
    "<form action='/a'></form>",
    "\n\t  <a href='/a'>A</a>\n\t",
    "<a href='/a'>A</a><a href='/a'>A</a>",
]


@pytest.mark.parametrize("html", BAD_HTML_INPUTS)
def test_extract_links_handles_bad_html_gracefully(html: str):
    result = extract_links(html, "https://example.com/", "example.com")
    assert isinstance(result, set)


BAD_SCRIPT_INPUTS = [
    "",
    "var x = 1;",
    "function f(){ return null; }",
    "/* no paths */",
    "// no paths",
    "'/a'",
    '"/a"',
    "'/api' '/api'",
    '"/api" "/api"',
    "'/api' \"api\" '/api'",
    "not a path",
    "123",
    "\x00",
    "<head></head>",
    "<html></html>",
    "plain text",
    "plain <tag> text",
    "<script>var x=1;</script>",
    "<script>var x=1;</script>   ",
    "\n",
    "\t",
    "\r\n",
    "   ",
    "  \n  ",
    "\x00</html>",
    "<html>\x00</html>",
]


@pytest.mark.parametrize("content", BAD_SCRIPT_INPUTS)
def test_scan_endpoints_handles_bad_script_gracefully(content: str):
    result = scan_endpoints("https://example.com/app.js", content)
    assert isinstance(result, list)


BAD_SECRET_INPUTS = [
    "",
    "var x = 1;",
    "function f(){ return null; }",
    "/* no secrets */",
    "// no secrets",
    "'/a'",
    '"/a"',
    "not a secret",
    "123",
    "\x00",
    "<html></html>",
    "plain text",
    "<script>var x=1;</script>",
    "<script>var x=1;</script>   ",
    "\n",
    "\t",
    "\r\n",
    "   ",
    "  \n  ",
    "\x00</html>",
    "<html>\x00</html>",
]


@pytest.mark.parametrize("content", BAD_SECRET_INPUTS)
def test_scan_secrets_handles_bad_content_gracefully(content: str):
    result = scan_secrets("https://example.com/app.js", content)
    assert isinstance(result, list)
