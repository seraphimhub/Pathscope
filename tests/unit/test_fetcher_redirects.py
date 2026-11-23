"""Tests for redirect handling limits and content guardrails in the fetcher."""

from __future__ import annotations

import asyncio
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import aiohttp
import pytest

from core.exceptions import FetchError
from crawler.fetcher import fetch, fetch_response


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RedirectChainHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/one":
            self.send_response(302)
            self.send_header("Location", "/two")
            self.end_headers()
        elif self.path == "/two":
            self.send_response(307)
            self.send_header("Location", "/final")
            self.end_headers()
        elif self.path == "/loop-a":
            self.send_response(302)
            self.send_header("Location", "/loop-b")
            self.end_headers()
        elif self.path == "/loop-b":
            self.send_response(302)
            self.send_header("Location", "/loop-a")
            self.end_headers()
        elif self.path.startswith("/hop"):
            number = int(self.path.removeprefix("/hop") or "0")
            self.send_response(302)
            self.send_header("Location", f"/hop{number + 1}")
            self.end_headers()
        elif self.path == "/binary":
            body = bytes(range(256))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"a" * 5000)
        elif self.path == "/missing":
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html>nope</html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html>final</html>")

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server() -> ThreadingHTTPServer:
    port = find_free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), RedirectChainHandler)
    thread = __import__("threading").Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


@pytest.mark.asyncio
async def test_redirect_chain_is_followed_and_reported(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        result = await fetch_response(session, base_url(server) + "/one")

    assert result.ok is True
    assert result.url == base_url(server) + "/final"
    assert result.redirects == (base_url(server) + "/two", base_url(server) + "/final")
    assert "final" in result.text


@pytest.mark.asyncio
async def test_redirect_loop_is_detected(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        with pytest.raises(FetchError) as excinfo:
            await fetch_response(session, base_url(server) + "/loop-a")
    assert "loop" in excinfo.value.reason


@pytest.mark.asyncio
async def test_redirect_hop_limit_is_enforced(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        with pytest.raises(FetchError) as excinfo:
            await fetch_response(session, base_url(server) + "/hop0", max_redirects=2)
    assert "redirect" in excinfo.value.reason


@pytest.mark.asyncio
async def test_redirect_guard_can_veto_a_hop(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        with pytest.raises(FetchError) as excinfo:
            await fetch_response(
                session,
                base_url(server) + "/one",
                allow_redirect_to=lambda target: False,
            )
    assert "rejected" in excinfo.value.reason


@pytest.mark.asyncio
async def test_binary_content_is_not_returned_as_text(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        result = await fetch_response(session, base_url(server) + "/binary")

    assert result.ok is True
    assert result.text == ""


@pytest.mark.asyncio
async def test_response_size_is_capped(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        result = await fetch_response(session, base_url(server) + "/large", max_bytes=1000)

    assert result.truncated is True
    assert len(result.text) == 1000


@pytest.mark.asyncio
async def test_error_status_body_is_dropped(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        result = await fetch_response(session, base_url(server) + "/missing")

    assert result.status == 404
    assert result.text == ""


@pytest.mark.asyncio
async def test_fetch_returns_text_for_success(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        text = await fetch(session, base_url(server) + "/one")

    assert "final" in text


@pytest.mark.asyncio
async def test_fetch_without_session_returns_empty_string(server: ThreadingHTTPServer) -> None:
    assert await fetch(None, base_url(server) + "/one") == ""


def test_redirect_loop_detection_runs_under_asyncio(server: ThreadingHTTPServer) -> None:
    """The loop guard must work through ``asyncio.run`` as well (no event-loop leak)."""

    async def go() -> str:
        async with aiohttp.ClientSession() as session:
            try:
                await fetch(session, base_url(server) + "/loop-a")
            except FetchError as exc:
                return str(exc)
            return ""

    assert "loop" in asyncio.run(go())
