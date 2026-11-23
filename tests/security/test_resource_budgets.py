"""Hostile servers cannot make a scan download or run without bound."""

from __future__ import annotations

import asyncio
import gzip
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import aiohttp
import pytest

from crawler.engine import Engine
from crawler.fetcher import fetch_response


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class HostileHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        HostileHandler.hits.append(self.path)
        if self.path == "/bomb":
            self._gzip_bomb()
        elif self.path == "/big" or self.path.startswith("/big/"):
            self._html(self._many_links("/big", 40) + "x" * 4000)
        elif self.path == "/links":
            self._html(self._many_links("/leaf", 5000))
        elif self.path.startswith("/leaf"):
            self._html("leaf")
        elif self.path == "/slow" or self.path.startswith("/slow/"):
            time.sleep(0.15)
            self._html(self._many_links("/slow", 30))
        elif self.path == "/query":
            links = "".join(f'<a href="/search?q={i}&page={i}">q</a>' for i in range(30))
            self._html(links)
        elif self.path == "/long":
            self._html('<a href="/' + "a" * 3000 + '">long</a>')
        elif self.path.startswith("/trap"):
            number = int(self.path.rsplit("/", 1)[-1] or "0")
            links = "".join(
                f'<a href="/trap/{number * 20 + offset}">next</a>' for offset in range(20)
            )
            self._html(links)
        else:
            self._html("ok")

    def _many_links(self, prefix: str, count: int) -> str:
        return "".join(f'<a href="{prefix}/{i}">n</a>' for i in range(count))

    def _html(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _gzip_bomb(self) -> None:
        payload = gzip.compress(b"A" * 5_000_000)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture()
def server() -> ThreadingHTTPServer:
    HostileHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), HostileHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_size_cap_applies_to_decoded_gzip_bytes(server: ThreadingHTTPServer) -> None:
    async with aiohttp.ClientSession() as session:
        result = await fetch_response(
            session,
            base_url(server) + "/bomb",
            max_bytes=10_000,
            timeout=10,
        )

    assert result.status == 200
    assert result.truncated is True
    assert len(result.text) <= 10_000
    # The cap is enforced on decoded bytes, not on the tiny compressed body.
    assert result.decoded_bytes <= 10_000


def test_engine_aborts_a_gzip_bomb_cleanly(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(server) + "/bomb",
        depth=0,
        workers=1,
        max_bytes=10_000,
        max_total_bytes=5000,
        max_time=10,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = read_json(tmp_path / "scan.json")
    assert metadata["stop_reason"] == "max_total_bytes"
    assert metadata["budgets"]["bytes_downloaded"] == 5000
    assert metadata["errors"] == []


def test_total_download_budget_stops_cleanly(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(server) + "/big",
        depth=1,
        workers=2,
        max_total_bytes=6000,
        max_pages=100,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = read_json(tmp_path / "scan.json")
    assert metadata["stop_reason"] == "max_total_bytes"
    assert metadata["budgets"]["bytes_downloaded"] == 6000
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    budget_events = [event for event in events if event["event"] == "budget_exhausted"]
    assert budget_events
    assert budget_events[0]["reason"].startswith("max_total_bytes")


def test_wall_clock_budget_stops_cleanly(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    started = time.perf_counter()
    engine = Engine(
        base_url(server) + "/slow",
        depth=2,
        workers=2,
        max_time=0.25,
        timeout=5,
        max_pages=1000,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())
    elapsed = time.perf_counter() - started

    metadata = read_json(tmp_path / "scan.json")
    assert metadata["stop_reason"] == "max_time"
    assert elapsed < 3
    assert metadata["elapsed"] < 3


def test_crawler_trap_terminates_at_page_budget(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    started = time.perf_counter()
    engine = Engine(
        base_url(server) + "/trap/0",
        depth=50,
        workers=4,
        max_pages=12,
        max_time=10,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())
    elapsed = time.perf_counter() - started

    metadata = read_json(tmp_path / "scan.json")
    assert metadata["stop_reason"] == "max_pages"
    assert metadata["counters"]["pages"] <= 12
    assert elapsed < 5
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(event["event"] == "budget_exhausted" for event in events)


def test_links_per_page_and_url_length_are_bounded(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(
        base_url(server) + "/links",
        depth=1,
        workers=2,
        max_pages=5000,
        max_links_per_page=10,
        max_url_length=80,
        max_time=10,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())
    metadata = read_json(tmp_path / "scan.json")
    assert metadata["budgets"]["links_suppressed"] >= 4000
    assert metadata["counters"]["pages"] <= 11

    second = Engine(
        base_url(server) + "/long",
        depth=1,
        workers=1,
        max_url_length=80,
        max_pages=10,
        output_dir=str(tmp_path / "long"),
    )
    asyncio.run(second.run())
    long_metadata = read_json(tmp_path / "long" / "scan.json")
    assert long_metadata["budgets"]["links_suppressed"] >= 1
    assert long_metadata["counters"]["pages"] == 1


def test_query_variant_budget_is_recorded(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(server) + "/query",
        depth=1,
        workers=1,
        max_query_variants=5,
        max_pages=100,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = read_json(tmp_path / "scan.json")
    assert metadata["budgets"]["query_variants_suppressed"] >= 25
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(event["event"] == "budget_exhausted" for event in events)


def test_a_single_failed_url_never_aborts_the_scan(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(
        base_url(server) + "/missing",
        depth=0,
        workers=1,
        max_time=5,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())
    metadata = read_json(tmp_path / "scan.json")
    assert metadata["stop_reason"] is None
    assert (tmp_path / "findings.json").is_file()
