"""Non-canonical numeric hosts are canonicalized before yarl/aiohttp sees them."""

from __future__ import annotations

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from core.security import canonicalize_request_url
from crawler.engine import Engine


class Handler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        Handler.hits.append(self.path)
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", f"http://2130706433:{self.server.server_port}/final")
            self.end_headers()
            return
        payload = b"<html><body>canonical</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


def test_canonicalize_request_url_rewrites_legacy_ipv4() -> None:
    assert canonicalize_request_url("http://2130706433:8080/x?y=1") == (
        "http://127.0.0.1:8080/x?y=1"
    )
    assert canonicalize_request_url("http://0x7f000001/") == "http://127.0.0.1/"
    assert canonicalize_request_url("https://example.com/") == "https://example.com/"
    assert canonicalize_request_url("http://[::1]:8080/") == "http://[::1]:8080/"


@pytest.fixture()
def server() -> ThreadingHTTPServer:
    Handler.hits = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def test_engine_scans_and_follows_redirects_from_numeric_host(
    server: ThreadingHTTPServer,
) -> None:
    engine = Engine(
        f"http://2130706433:{server.server_port}/",
        depth=0,
        workers=1,
        timeout=5,
        persist=False,
    )
    asyncio.run(engine.run())

    assert engine.pages_fetched == 1
    assert engine.errors == []
    assert engine.redirects_followed == 1
    assert "/final" in Handler.hits
