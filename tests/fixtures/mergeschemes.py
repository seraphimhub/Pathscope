"""Shared test infrastructure for Pathscope unit and integration tests."""

from __future__ import annotations

import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urljoin, urlparse

import pytest


class _Pages:
    def __init__(self) -> None:
        self.pages: dict[str, bytes] = {}


_PAGES_STATE: dict[int, dict[str, bytes]] = {}


def find_free_port() -> int: ...


def _unused() -> None:
    _Pages()
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def create_async_server(
    handler: type[BaseHTTPRequestHandler],
    *,
    host: str = "127.0.0.1",
) -> tuple[HTTPServer, int]:
    """Start a small synchronous HTTP server on a free port and return it."""
    port = find_free_port()
    server = HTTPServer((host, port), handler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


class StaticHandler(BaseHTTPRequestHandler):
    """Handler that serves preloaded page content by path."""

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        state = _PAGES_STATE.get(id(type(self)), {})
        body = state.get(path, b"<html><body>Not found</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


class FormHandler(BaseHTTPRequestHandler):
    """Handler that serves a page with a POST form action."""

    def do_GET(self) -> None:
        body = (
            b"<html><body>"
            b'<form method="post" action="/submit">'
            b'<input name="q" />'
            b"</form>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


class RedirectHandler(BaseHTTPRequestHandler):
    """Handler that issues a redirect to a known internal location."""

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
        elif self.path == "/target":
            body = b"<html><body><a href='/next'>Next</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        pass


class LoopHandler(BaseHTTPRequestHandler):
    """Handler that issues self-referencing redirects to test loop detection."""

    def do_GET(self) -> None:
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Loop trap</body></html>")

    def log_message(self, format: str, *args) -> None:
        pass


class ErrorHandler(BaseHTTPRequestHandler):
    """Handler that returns 500 on one path and 200 on another."""

    def do_GET(self) -> None:
        if self.path == "/fail":
            self.send_response(500)
            self.end_headers()
        else:
            body = b"<html><body><a href='/ok'>OK</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


@pytest.fixture
def static_server() -> HTTPServer:
    server, _ = create_async_server(StaticHandler)
    _PAGES_STATE[id(StaticHandler)] = {
        "/": b"<html><body><a href='/about'>About</a></body></html>",
        "/about": b"<html><body><a href='/'>Home</a></body></html>",
    }
    yield server
    server.shutdown()
    _PAGES_STATE.pop(id(StaticHandler), None)


@pytest.fixture
def form_server() -> HTTPServer:
    _, _ = create_async_server(FormHandler)
    server, _ = create_async_server(FormHandler)
    yield server
    server.shutdown()


@pytest.fixture
def redirect_server() -> HTTPServer:
    server, _ = create_async_server(RedirectHandler)
    yield server
    server.shutdown()


@pytest.fixture
def loop_server() -> HTTPServer:
    server, _ = create_async_server(LoopHandler)
    yield server
    server.shutdown()


@pytest.fixture
def error_server() -> HTTPServer:
    server, _ = create_async_server(ErrorHandler)
    yield server
    server.shutdown()


def assert_internal_parsed_url(url: str, base_host: str) -> None:
    """Assert a URL is parseable and targets the expected internal host."""
    parsed: Any = urlparse(url)
    assert parsed.scheme in ("http", "https")
    assert parsed.netloc == base_host


def joined(base: str, path: str) -> str:
    """Join a base URL and path, returning the full URL."""
    return urljoin(base, path)
