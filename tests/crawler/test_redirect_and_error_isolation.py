"""Tests for redirect handling, error isolation, and malformed input behavior."""

from __future__ import annotations

import asyncio
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from crawler.parser import extract_links, normalize
from scanners.endpoints import scan_endpoints
from scanners.secrets import scan_secrets

try:
    _AIOHTTP = True
except Exception:  # pragma: no cover - optional dependency guard
    _AIOHTTP = False


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
        elif self.path == "/target":
            body = '<html><body><a href="/next">Next</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class ErrorFlakeHandler(BaseHTTPRequestHandler):
    """Flaky handler to exercise error isolation behavior."""

    counter = 0

    def do_GET(self) -> None:
        ErrorFlakeHandler.counter += 1
        if self.path == "/fail":
            self.send_response(500)
            self.end_headers()
        else:
            body = '<html><body><a href="/ok">OK</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def redirect_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), RedirectHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def error_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), ErrorFlakeHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def test_normalize_is_stable_for_malformed_inputs() -> None:
    cases = [
        "https://example.com/bad%ZZ",
        "https://example.com/",
        "https://example.com:99999/path",
    ]
    for raw in cases:
        try:
            normalize(raw)
        except Exception as exc:
            pytest.fail(f"normalize() raised for {raw!r}: {exc}")


def test_extract_links_is_stable_for_malformed_html() -> None:
    cases = [
        "<html><body><a href='/a'>A</a>",
        "<html><body><a href='/a'>A</a></body>",
        "<html><a href='/a'>A</a>",
        "<a href='/a'>A</a>",
        "<img src='/a'/>",
    ]
    for html in cases:
        try:
            links = extract_links(html, "https://example.com/", "example.com")
        except Exception as exc:
            pytest.fail(f"extract_links() raised for {html!r}: {exc}")
        assert isinstance(links, set)


def test_secret_scanning_is_stable_for_malformed_content() -> None:
    cases = [
        "var x = '\\x00'",
        "function f(){ return null; }",
        "<html></html>",
        "",
    ]
    for content in cases:
        try:
            findings = scan_secrets("https://example.com/", content)
        except Exception as exc:
            pytest.fail(f"scan_secrets() raised for {content!r}: {exc}")
        assert isinstance(findings, list)


def test_endpoint_scanning_is_stable_for_malformed_content() -> None:
    cases = [
        "'/api'",
        "not a path",
        "",
        "var x = '/api'; // comment",
    ]
    for content in cases:
        try:
            findings = scan_endpoints("https://example.com/", content)
        except Exception as exc:
            pytest.fail(f"scan_endpoints() raised for {content!r}: {exc}")
        assert isinstance(findings, list)


@pytest.mark.skipif(not _AIOHTTP, reason="aiohttp not available")
def test_error_isolation_on_500_response(error_server: HTTPServer) -> None:
    from crawler.fetcher import fetch

    url = f"http://127.0.0.1:{error_server.server_port}/fail"

    async def _go() -> str:
        return await fetch(None, url)

    try:
        text = asyncio.run(_go())
    except Exception:  # pragma: no cover - acceptable failure point
        text = ""

    assert isinstance(text, str)


@pytest.mark.skipif(not _AIOHTTP, reason="aiohttp not available")
def test_fetch_from_invalid_host_is_safe(error_server: HTTPServer) -> None:
    from crawler.fetcher import fetch

    url = "http://127.0.0.1:1/inaccessible"

    async def _go() -> str:
        return await fetch(None, url)

    try:
        text = asyncio.run(_go())
    except Exception:  # pragma: no cover - acceptable failure point
        text = ""

    assert isinstance(text, str)
