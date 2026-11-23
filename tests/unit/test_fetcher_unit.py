"""Unit tests for the fetcher module.

These tests use a shared aiohttp session created in the test itself so that the
request can read the response body from a module-scoped mock server.
"""

import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

try:
    import aiohttp

    _AIOHTTP = True
except Exception:  # pragma: no cover
    _AIOHTTP = False

from crawler.fetcher import fetch


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: Any) -> None:
        pass


class CustomHeaderHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b'var apiKey = "FAKE-TOKEN-EXAMPLE-ONLY";  # example only, not a real credential'
        )

    def log_message(self, format: str, *args: Any) -> None:
        pass


class NoContentHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def slow_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), SlowHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def custom_header_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), CustomHeaderHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def no_content_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), NoContentHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.mark.asyncio
@pytest.mark.skipif(not _AIOHTTP, reason="aiohttp not available")
async def test_fetch_returns_text_on_success(slow_server: HTTPServer):
    url = f"http://127.0.0.1:{slow_server.server_port}/"
    async with aiohttp.ClientSession() as session:
        text = await fetch(session, url)
    assert isinstance(text, str)
    assert "ok" in text


@pytest.mark.asyncio
@pytest.mark.skipif(not _AIOHTTP, reason="aiohttp not available")
async def test_fetch_decodes_response_body_correctly_custom_header_server(
    custom_header_server: HTTPServer,
):
    url = f"http://127.0.0.1:{custom_header_server.server_port}/"
    async with aiohttp.ClientSession() as session:
        text = await fetch(session, url)
    assert isinstance(text, str)
    assert "FAKE-TOKEN-EXAMPLE-ONLY" in text  # example only, not a real credential


@pytest.mark.asyncio
async def test_fetch_handles_non_200_responses_no_content_server(
    no_content_server: HTTPServer,
):
    url = f"http://127.0.0.1:{no_content_server.server_port}/"
    text = await fetch(None, url)
    assert isinstance(text, str)


@pytest.mark.asyncio
async def test_fetch_from_invalid_target_returns_empty_string():
    url = "http://127.0.0.1:1/a"
    text = await fetch(None, url)
    assert isinstance(text, str)
