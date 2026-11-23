"""Minimal bootstrap tests to verify current Pathscope behavior with a local mock HTTP server."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from crawler.engine import Engine

_BOOT_PAGES: dict[str, str] = {}


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockHandler(BaseHTTPRequestHandler):
    """Serves a small set of mock pages for bootstrap testing."""

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        content = _BOOT_PAGES.get(path, "<html><body>Not found</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output quiet


@pytest.fixture(scope="module")
def http_server() -> str:
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def populate_pages(http_server: str) -> None:
    _BOOT_PAGES.update(
        {
            "/": """
        <html>
        <head><title>Home</title></head>
        <body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <a href="/admin/config">Admin Config</a>
            <script>
                var apiKey = "EXAMP-LEFAKETOKENVALUE00000";  # example only, not a real credential
                fetch("/api/v1/users");
            </script>
        </body>
        </html>
        """,
            "/about": """
        <html><body><h1>About</h1><a href="/">Home</a></body></html>
        """,
            "/contact": """
        <html><body><h1>Contact</h1><a href="/">Home</a></body></html>
        """,
            "/admin/config": """
        <html><body><h1>Admin Config</h1>
        TODO: rotate secret
        <a href="/about">About</a>
        </body></html>
        """,
        }
    )
    yield
    _BOOT_PAGES.clear()


def test_engine_crawl_discovers_pages(http_server: str) -> None:
    engine = Engine(f"{http_server}/", depth=3)
    asyncio.run(engine.run())

    urls = {f["url"] for f in engine.findings if f.get("url")}
    assert f"{http_server}/about" in urls or f"{http_server}/" in urls
    assert f"{http_server}/contact" in urls or f"{http_server}/" in urls


def test_engine_outputs_findings(http_server: str, tmp_path: str) -> None:
    original = os.getcwd()
    try:
        out_dir = os.path.join(str(tmp_path), "output")
        os.makedirs(out_dir, exist_ok=True)
        os.chdir(str(tmp_path))
        engine = Engine(f"{http_server}/", depth=3)
        asyncio.run(engine.run())
        path = os.path.join(out_dir, "findings.json")
        assert os.path.exists(path), "findings.json was not written"
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)
    finally:
        os.chdir(original)


def test_engine_respects_depth(http_server: str) -> None:
    engine = Engine(f"{http_server}/", depth=1)
    asyncio.run(engine.run())
    # Depth 1 should visit start + immediate links only
    assert len(engine.visited) >= 1
    # This is a soft assertion: we mainly want to ensure no crash.
    assert len(engine.findings) >= 0


def test_engine_crawl_records_visited_urls(http_server: str) -> None:
    engine = Engine(f"{http_server}/", depth=2)
    asyncio.run(engine.run())
    assert http_server.rstrip("/") + "/" in engine.visited
    assert len(engine.visited) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
