"""Regression tests for worker bounds, error isolation, caps and dedup."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from crawler.engine import Engine

SLOW_PAGES = 6
PAGE_COUNT = 20


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CrawlHandler(BaseHTTPRequestHandler):
    """Multi-scenario mock site used by the engine tests."""

    lock = threading.Lock()
    active = 0
    max_active = 0

    def do_GET(self) -> None:
        with CrawlHandler.lock:
            CrawlHandler.active += 1
            CrawlHandler.max_active = max(CrawlHandler.max_active, CrawlHandler.active)
        try:
            self._route()
        finally:
            with CrawlHandler.lock:
                CrawlHandler.active -= 1

    def _route(self) -> None:
        path = self.path
        if path == "/conc":
            links = "".join(f'<a href="/slow{i}">s{i}</a>' for i in range(SLOW_PAGES))
            self._html(f"<html><body>{links}</body></html>")
        elif path.startswith("/slow"):
            time.sleep(0.08)
            self._html("<html><body>slow</body></html>")
        elif path == "/iso":
            self._html('<html><body><a href="/ok">ok</a><a href="/boom">boom</a></body></html>')
        elif path == "/boom":
            # Abrupt close exercises connection-level failure isolation.
            self.close_connection = True
            self.connection.close()
        elif path == "/ok":
            self._html('<html><body><a href="/api/v1/health">health</a></body></html>')
        elif path == "/redir":
            self._html('<html><body><a href="/r">r</a></body></html>')
        elif path == "/r":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/out")
            self.end_headers()
        elif path == "/pages":
            links = "".join(f'<a href="/m{i}">m{i}</a>' for i in range(PAGE_COUNT))
            self._html(f"<html><body>{links}</body></html>")
        elif path.startswith("/m"):
            self._html("<html><body>leaf</body></html>")
        elif path == "/dupes":
            self._html('<html><body><a href="/dupe-a">a</a><a href="/dupe-b">b</a></body></html>')
        elif path in {"/dupe-a", "/dupe-b"}:
            self._html('<html><body><script>fetch("/api/v1/users")</script></body></html>')
        else:
            self._html("<html><body>root</body></html>")

    def _html(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), CrawlHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def test_worker_count_bounds_concurrent_requests(server: ThreadingHTTPServer) -> None:
    with CrawlHandler.lock:
        CrawlHandler.active = 0
        CrawlHandler.max_active = 0

    engine = Engine(base_url(server) + "/conc", depth=1, workers=2, persist=False)
    asyncio.run(engine.run())

    assert engine.pages_fetched >= SLOW_PAGES
    assert CrawlHandler.max_active <= 2, "engine exceeded its worker bound"
    assert CrawlHandler.max_active >= 2, "engine never used its concurrency budget"


def test_single_failing_url_does_not_abort_the_crawl(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/iso", depth=1, workers=4, persist=False)
    asyncio.run(engine.run())

    visited_paths = {url.split("://", 1)[1].split("/", 1)[1] for url in engine.visited}
    assert any(path.startswith("ok") for path in visited_paths)
    assert any("/boom" in error["url"] for error in engine.errors)
    for error in engine.errors:
        assert {"url", "type", "reason"} <= set(error)


def test_redirect_out_of_scope_is_refused(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/redir", depth=2, workers=2, persist=False)
    asyncio.run(engine.run())

    assert all("example.invalid" not in url for url in engine.visited)
    assert all("example.invalid" not in item.url for item in engine.discovered_urls)
    # The blocked hop is recorded against the page that requested it.
    assert any("example.invalid" in error["reason"] for error in engine.errors)
    assert any(error["url"].endswith("/r") for error in engine.errors)


def test_max_pages_cap_is_enforced(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/pages", depth=2, workers=4, max_pages=3, persist=False)
    asyncio.run(engine.run())

    assert len(engine.visited) <= 3
    assert engine.pages_fetched <= 3


def test_duplicate_endpoints_are_reported_once(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/dupes", depth=2, workers=2, persist=False)
    asyncio.run(engine.run())

    endpoints = [finding["endpoint"] for finding in engine.endpoints]
    assert endpoints.count("/api/v1/users") == 1


def test_engine_records_elapsed_and_discovery_provenance(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/pages", depth=1, workers=4, persist=False)
    asyncio.run(engine.run())

    assert engine.elapsed > 0
    assert engine.discovered_urls
    seed = engine.discovered_urls[0]
    assert seed.discovery_method == "seed"
    assert seed.crawled is True
    child = next(item for item in engine.discovered_urls if item.discovery_method == "link")
    assert child.depth == 1
    assert child.source_url


def test_engine_refuses_private_target_when_policy_requires(
    server: ThreadingHTTPServer,
) -> None:
    from core.exceptions import ScopeViolationError

    engine = Engine(base_url(server) + "/", depth=0, block_private=True, persist=False)
    with pytest.raises(ScopeViolationError):
        asyncio.run(engine.run())
