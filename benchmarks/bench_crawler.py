"""Baseline crawler benchmark harness.

Run with: .venv/bin/python -m benchmarks.bench_crawler

This script starts a local mock server, runs the current crawl engine against it
at a few concurrency levels, and reports elapsed time, URLs processed, and
per-second throughput. It is intended to be reproducible and to detect regressions
after engine changes.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urljoin

import click

from crawler.engine import Engine

PAGE_COUNT = 40
LINK_DENSITY = 4  # new links per page, creating a denser graph
MAX_DEPTH = 6

_PAGES_FOR_HOST: dict[int, dict[str, str]] = {}


class BenchHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        state = _PAGES_FOR_HOST.get(id(type(self)), {})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = state.get(self.path, "<html><body>Empty</body></html>")
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        pass


def build_page_graph(base: str, index: int) -> str:
    links: list[str] = []
    for i in range(LINK_DENSITY):
        neighbor = (index + i + 1) % PAGE_COUNT
        links.append(f'<a href="{urljoin(base, "/" + str(neighbor))}">{neighbor}</a>')
    return f"<html><body><h1>Page {index}</h1>{''.join(links)}</body></html>"


def prepare_pages(base: str) -> dict[str, str]:
    pages: dict[str, str] = {}
    for i in range(PAGE_COUNT):
        pages[f"/{i}"] = build_page_graph(base, i)
    return pages


def find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class BenchmarkResult:
    concurrency: int
    elapsed: float
    urls_visited: int
    urls_per_second: float
    findings_count: int


async def run_once(server_url: str, depth: int, concurrency: int) -> BenchmarkResult:
    engine = Engine(server_url, depth=depth)
    start = time.perf_counter()
    await engine.run()
    elapsed = time.perf_counter() - start
    return BenchmarkResult(
        concurrency=concurrency,
        elapsed=elapsed,
        urls_visited=len(engine.visited),
        urls_per_second=len(engine.visited) / max(elapsed, 1e-6),
        findings_count=len(engine.findings),
    )


async def main_async(
    host: str,
    port: int,
    depth: int,
    runs: int,
    concurrency_levels: list[int],
) -> None:
    base = f"http://{host}:{port}"
    _PAGES_FOR_HOST[id(BenchHandler)] = prepare_pages(base)

    results: list[BenchmarkResult] = []
    for concurrency in concurrency_levels:
        run_res = await run_once(base, depth, concurrency)
        results.append(run_res)
        print(
            json.dumps(
                {
                    "concurrency": concurrency,
                    "elapsed": round(run_res.elapsed, 3),
                    "urls_visited": run_res.urls_visited,
                    "urls_per_second": round(run_res.urls_per_second, 2),
                    "findings": run_res.findings_count,
                }
            )
        )

    print("\n== Benchmark complete ==")
    for r in results:
        print(
            f"concurrency={r.concurrency}: {r.urls_per_second:.2f} URLs/s, "
            f"{r.urls_visited} visited, {r.elapsed:.3f}s"
        )


@click.command()
@click.option("--host", default="127.0.0.1", help="bind address for mock server")
@click.option("--port", default=0, type=int, help="port for mock server (0 = auto)")
@click.option("--depth", default=MAX_DEPTH, type=int, help="crawl depth")
@click.option("--runs", default=1, type=int, help="repeated runs per concurrency level")
@click.option("--levels", default="1,4,8", help="comma-separated concurrency levels")
def main(
    host: str,
    port: int,
    depth: int,
    runs: int,
    levels: str,
) -> None:
    concurrency_levels = [int(x.strip()) for x in levels.split(",") if x.strip()]
    server_port = port or find_free_port()
    server = HTTPServer((host, server_port), BenchHandler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        asyncio.run(main_async(host, server_port, depth, runs, concurrency_levels))
    finally:
        server.shutdown()
        _PAGES_FOR_HOST.pop(id(BenchHandler), None)


if __name__ == "__main__":
    main()
