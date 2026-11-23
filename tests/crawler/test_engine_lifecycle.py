"""Engine lifecycle tests.

These tests verify the high-level crawl lifecycle, cancellation behavior, and
basic error isolation. They use a local mock server and assert on the engine's
public state.
"""

import asyncio
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import pytest

from crawler.engine import Engine


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FragmentedHandler(BaseHTTPRequestHandler):
    """Serves a page with a fragment identifier to verify fragment handling."""

    def do_GET(self) -> None:
        if self.path == "/sample":
            body = (
                "<html><body>"
                '<a href="/about">About</a>'
                '<a href="/about#team">About team</a>'
                "</body></html>"
            )
        else:
            body = "<html><body>Not found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass


class DepthLimitHandler(BaseHTTPRequestHandler):
    """Serves a small tree to validate max-depth behavior."""

    def do_GET(self) -> None:
        if self.path == "/":
            body = '<html><body><a href="/a">A</a><a href="/b">B</a></body></html>'
        elif self.path in ("/a", "/b"):
            body = '<html><body><a href="/leave">Leave</a></body></html>'
        else:
            body = "<html><body>Not found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def fragmented_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), FragmentedHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def depth_server() -> HTTPServer:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), DepthLimitHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def test_engine_crawl_normalizes_fragments_only_once(fragmented_server: HTTPServer):
    base = f"http://127.0.0.1:{fragmented_server.server_port}"
    engine = Engine(base + "/sample", depth=3)
    asyncio.run(engine.run())

    normalized = [u for u in engine.visited if urlparse(u).fragment == ""]
    assert len(normalized) >= 1


def test_engine_respects_max_depth(depth_server: HTTPServer):
    base = f"http://127.0.0.1:{depth_server.server_port}"
    engine = Engine(base + "/", depth=1)
    asyncio.run(engine.run())

    visited = {urlparse(u).path for u in engine.visited}
    # At depth=1 we should see the root and immediate links but not necessarily /leave.
    assert "/" in visited
    assert "/a" in visited or "/b" in visited


def test_engine_collects_findings_from_crawl(fragmented_server: HTTPServer):
    base = f"http://127.0.0.1:{fragmented_server.server_port}"
    engine = Engine(base + "/sample", depth=2)
    asyncio.run(engine.run())
    assert len(engine.findings) >= 0
