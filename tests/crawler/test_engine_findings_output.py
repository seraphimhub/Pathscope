"""Findings dedup, endpoint provenance, scan metadata and atomic output.

These pin Phase 0 behaviour: the same secret pattern on the same line of two
different pages is two findings, an endpoint seen on several pages is one
finding that lists every page, and a scan persists its metadata plus every
error in a file only the owner can read.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

import crawler.engine as engine_module
from crawler.engine import Engine


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FindingsHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []
    redirect_target: ClassVar[str] = ""

    def do_GET(self) -> None:
        FindingsHandler.hits.append(self.path)
        path = self.path
        if path == "/root":
            self._html('<a href="/a">a</a><a href="/b">b</a>')
        elif path in {"/a", "/b"}:
            # Identical line number and pattern on two different pages.
            self._html('<html><body>\nvar api_key = "EXAMPLE_PLACEHOLDER_VALUE_123";</body></html>')
        elif path == "/shared":
            self._html(
                '<html><body><script>fetch("/api/v1/users")</script>'
                '<a href="/shared-a">a</a><a href="/shared-b">b</a></body></html>'
            )
        elif path in {"/shared-a", "/shared-b"}:
            self._html('<html><body><script>fetch("/api/v1/users")</script></body></html>')
        elif path == "/boom":
            self.close_connection = True
            self.connection.close()
        elif path == "/go":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
        elif path == "/port-go":
            self.send_response(302)
            self.send_header("Location", FindingsHandler.redirect_target)
            self.end_headers()
        else:
            self._html("<html><body>final</body></html>")

    def _html(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


class OtherServerHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        OtherServerHandler.hits.append(self.path)
        payload = b"<html><body>other</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server() -> ThreadingHTTPServer:
    FindingsHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), FindingsHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


@pytest.fixture()
def other_server() -> ThreadingHTTPServer:
    OtherServerHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), OtherServerHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_same_secret_pattern_on_same_line_of_two_pages_is_two_findings(
    server: ThreadingHTTPServer,
) -> None:
    engine = Engine(base_url(server) + "/root", depth=1, workers=2, persist=False)
    asyncio.run(engine.run())

    secrets = [f for f in engine.findings if f.get("type") == "secret_pattern"]
    api_findings = [f for f in secrets if f.get("pattern") == r"api[_-]?key"]
    assert len(api_findings) == 2, "secret findings from different pages must not collapse"
    assert {finding["url"] for finding in api_findings} == {
        base_url(server) + "/a",
        base_url(server) + "/b",
    }
    assert {finding["line"] for finding in api_findings} == {2}


def test_endpoint_seen_on_several_pages_lists_every_page(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/shared", depth=2, workers=2, persist=False)
    asyncio.run(engine.run())

    endpoints = [f for f in engine.findings if f.get("endpoint") == "/api/v1/users"]
    assert len(endpoints) == 1, "endpoints stay globally deduplicated"
    pages = set(endpoints[0]["pages"])
    assert base_url(server) + "/shared" in pages
    assert base_url(server) + "/shared-a" in pages
    assert base_url(server) + "/shared-b" in pages
    assert endpoints[0]["pages"][0] == base_url(server) + "/shared"


def test_endpoint_pages_are_not_duplicated(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/shared-a", depth=0, workers=1, persist=False)
    asyncio.run(engine.run())

    endpoint = next(f for f in engine.findings if f.get("endpoint") == "/api/v1/users")
    assert endpoint["pages"] == [base_url(server) + "/shared-a"]


# ---------------------------------------------------------------------------
# Redirect scope: same host, different port
# ---------------------------------------------------------------------------


def test_redirect_to_another_port_is_refused(
    server: ThreadingHTTPServer, other_server: ThreadingHTTPServer
) -> None:
    FindingsHandler.redirect_target = f"http://127.0.0.1:{other_server.server_port}/other"
    try:
        engine = Engine(base_url(server) + "/port-go", depth=1, workers=1, persist=False)
        asyncio.run(engine.run())
    finally:
        FindingsHandler.redirect_target = ""

    assert OtherServerHandler.hits == [], "a redirect to another port must not be followed"
    assert any("rejected by scope policy" in error["reason"] for error in engine.errors)


# ---------------------------------------------------------------------------
# Discovery bookkeeping
# ---------------------------------------------------------------------------


def test_redirected_page_is_marked_crawled_under_requested_url(
    server: ThreadingHTTPServer,
) -> None:
    engine = Engine(base_url(server) + "/go", depth=0, workers=1, persist=False)
    asyncio.run(engine.run())

    assert engine.discovered_urls[0].crawled is True
    assert engine.discovered_urls[0].url == base_url(server) + "/final"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_scan_metadata_and_errors_are_persisted(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    output_dir = str(tmp_path)
    engine = Engine(
        base_url(server) + "/boom",
        depth=0,
        workers=1,
        persist=True,
        output_dir=output_dir,
    )
    asyncio.run(engine.run())

    findings_path = os.path.join(output_dir, "findings.json")
    scan_path = os.path.join(output_dir, "scan.json")
    assert os.path.isfile(findings_path)
    assert os.path.isfile(scan_path)

    with open(findings_path, encoding="utf-8") as handle:
        assert isinstance(json.load(handle), list)

    with open(scan_path, encoding="utf-8") as handle:
        metadata = json.load(handle)

    assert metadata["target"] == base_url(server) + "/boom"
    assert metadata["scope"] == f"127.0.0.1:{server.server_port}"
    assert metadata["counters"]["pages"] == 0
    assert metadata["elapsed"] >= 0
    assert metadata["errors"], "a failed fetch must be persisted, not only logged"
    assert metadata["errors"][0]["url"] == base_url(server) + "/boom"
    assert {"url", "type", "reason"} <= set(metadata["errors"][0])

    for path in (findings_path, scan_path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"{path} must be readable by the owner only, got {oct(mode)}"


def test_failed_write_leaves_previous_output_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir = str(tmp_path)
    path = os.path.join(output_dir, "findings.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write('[{"type": "previous"}]')

    engine = Engine("http://127.0.0.1:1/", persist=True, output_dir=output_dir)

    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(engine_module.json, "dump", explode)

    with pytest.raises(RuntimeError):
        engine.write_findings()

    with open(path, encoding="utf-8") as handle:
        assert handle.read() == '[{"type": "previous"}]'
    leftovers = [name for name in os.listdir(output_dir) if name != "findings.json"]
    assert leftovers == [], f"temporary files left behind: {leftovers}"
