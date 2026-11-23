"""Baseline crawler benchmark harness.

Run with: .venv/bin/python -m benchmarks.bench_crawler

Starts a local multi-threaded mock site, then crawls it once per ``--levels``
value with ``Engine(workers=level)``. Each mocked request sleeps for
``--latency`` seconds, so the reported pages/second reflects the crawler's
actual parallelism rather than the speed of an in-memory lookup.

The harness is deterministic (fixed graph, fixed page count, best-of-N runs),
which makes it usable as a regression gate after engine changes.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urljoin

import click

from crawler.engine import Engine

PAGE_COUNT = 40
LINK_DENSITY = 4  # outgoing links per page
DEFAULT_DEPTH = 6
DEFAULT_LATENCY_MS = 10

_PAGES: dict[str, str] = {}


def build_page(index: int, base: str) -> str:
    links = []
    for offset in range(LINK_DENSITY):
        neighbor = (index + offset + 1) % PAGE_COUNT
        links.append(f'<a href="{urljoin(base, f"/p{neighbor}")}">p{neighbor}</a>')
    return (
        f"<html><body><h1>Page {index}</h1>"
        f"{''.join(links)}"
        '<script>fetch("/api/v1/items");</script>'
        "</body></html>"
    )


def prepare_pages(base: str) -> dict[str, str]:
    pages = {"/": f'<html><body><a href="{base}/p0">start</a></body></html>'}
    for index in range(PAGE_COUNT):
        pages[f"/p{index}"] = build_page(index, base)
    return pages


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class BenchHandler(BaseHTTPRequestHandler):
    """Serves the prepared page graph with an artificial per-request latency."""

    latency: ClassVar[float] = DEFAULT_LATENCY_MS / 1000
    pages: ClassVar[dict[str, str]] = {}

    def do_GET(self) -> None:
        time.sleep(self.latency)
        body = self.pages.get(self.path.split("?")[0], "<html><body>missing</body></html>")
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@dataclass
class BenchmarkResult:
    concurrency: int
    elapsed: float
    pages: int
    pages_per_second: float
    findings: int
    errors: int = 0


async def run_once(server_url: str, depth: int, concurrency: int) -> BenchmarkResult:
    # ``workers`` is the knob under test: the engine must honour it, otherwise
    # every level measures the same thing.
    engine = Engine(server_url, depth=depth, workers=concurrency, persist=False)
    started = time.perf_counter()
    await engine.run()
    elapsed = time.perf_counter() - started
    return BenchmarkResult(
        concurrency=concurrency,
        elapsed=elapsed,
        pages=engine.pages_fetched,
        pages_per_second=engine.pages_fetched / max(elapsed, 1e-6),
        findings=len(engine.findings),
        errors=len(engine.errors),
    )


async def main_async(
    host: str,
    port: int,
    depth: int,
    runs: int,
    concurrency_levels: list[int],
) -> list[BenchmarkResult]:
    base = f"http://{host}:{port}"
    BenchHandler.pages = prepare_pages(base)

    results: list[BenchmarkResult] = []
    repeats = max(1, runs)
    for concurrency in concurrency_levels:
        level_results: list[BenchmarkResult] = []
        for run_index in range(repeats):
            result = await run_once(base, depth, concurrency)
            level_results.append(result)
            print(
                json.dumps(
                    {
                        "concurrency": concurrency,
                        "run": run_index + 1,
                        "elapsed": round(result.elapsed, 3),
                        "pages": result.pages,
                        "pages_per_second": round(result.pages_per_second, 2),
                        "findings": result.findings,
                        "errors": result.errors,
                    }
                )
            )
        results.append(min(level_results, key=lambda item: item.elapsed))

    return results


@click.command()
@click.option("--host", default="127.0.0.1", help="bind address for the mock server")
@click.option("--port", default=0, type=int, help="port for the mock server (0 = auto)")
@click.option("--depth", default=DEFAULT_DEPTH, type=int, help="crawl depth")
@click.option("--runs", default=1, type=int, help="repeated runs per concurrency level")
@click.option("--levels", default="1,4,8", help="comma-separated worker counts")
@click.option(
    "--latency-ms",
    default=DEFAULT_LATENCY_MS,
    type=int,
    help="artificial per-request latency in milliseconds",
)
def main(
    host: str,
    port: int,
    depth: int,
    runs: int,
    levels: str,
    latency_ms: int,
) -> None:
    concurrency_levels = [int(item) for item in levels.split(",") if item.strip()]
    BenchHandler.latency = max(0, latency_ms) / 1000
    server_port = port or find_free_port()
    httpd = ThreadingHTTPServer((host, server_port), BenchHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        results = asyncio.run(main_async(host, server_port, depth, runs, concurrency_levels))
    finally:
        httpd.shutdown()
        BenchHandler.pages = {}

    print("\n== Benchmark complete (best run per level) ==")
    for result in results:
        print(
            f"workers={result.concurrency}: {result.pages_per_second:.2f} pages/s, "
            f"{result.pages} pages, {result.elapsed:.3f}s, "
            f"{result.findings} findings, {result.errors} errors"
        )


if __name__ == "__main__":
    main()
