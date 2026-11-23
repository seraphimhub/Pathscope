"""Reproducible crawler benchmark harness.

Run with: .venv/bin/python -m benchmarks.bench_crawler --scenario low-latency

Each scenario builds a fixed page graph and serves it from a local multi-threaded
HTTP server with a controllable per-request latency, so the reported throughput
reflects crawler parallelism rather than an in-memory lookup. Every level runs
``--runs`` times and the report shows the spread, because a single run is not a
performance measurement.

Metrics distinguish what is easy to confuse:

* ``graph_pages``   pages that exist in the synthetic site
* ``visited``       pages the crawler enqueued and attempted
* ``requests``      HTTP requests actually issued (redirects included)
* ``successes``     fetches with a 2xx status
* ``errors``        fetches that failed at the transport/policy level
* ``throughput``    successful fetches per second

Scenarios: ``low-latency``, ``high-latency``, ``slow-server``, ``flaky``,
``large``, ``duplicates``, or ``all``.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urljoin

import click

from crawler.engine import Engine

LINK_DENSITY = 4
ROOT_FANOUT = 8
DEFAULT_LEVELS = "1,2,4,8"
DEFAULT_RUNS = 3


@dataclass(frozen=True)
class Scenario:
    """Immutable description of a benchmark site and its behaviour."""

    name: str
    pages: int
    latency_ms: int
    page_bytes: int = 1024
    failure_every: int = 0
    duplicate_links: int = 1

    @property
    def latency(self) -> float:
        return max(0, self.latency_ms) / 1000


SCENARIOS: dict[str, Scenario] = {
    "low-latency": Scenario("low-latency", pages=40, latency_ms=5),
    "high-latency": Scenario("high-latency", pages=20, latency_ms=100),
    "slow-server": Scenario("slow-server", pages=10, latency_ms=300),
    "flaky": Scenario("flaky", pages=30, latency_ms=5, failure_every=5),
    "large": Scenario("large", pages=10, latency_ms=5, page_bytes=200_000),
    "duplicates": Scenario("duplicates", pages=10, latency_ms=5, duplicate_links=8),
}

_BASE = ""


def build_page(index: int, scenario: Scenario) -> str:
    links: list[str] = []
    for offset in range(LINK_DENSITY):
        neighbor = (index + offset + 1) % scenario.pages
        links.append(f'<a href="{urljoin(_BASE, f"/p{neighbor}")}">p{neighbor}</a>')

    if scenario.duplicate_links > 1:
        duplicates = "".join(
            f'<a href="{urljoin(_BASE, f"/p{(index + 1) % scenario.pages}")}">dup</a>'
            for _ in range(scenario.duplicate_links)
        )
        links.append(duplicates)

    filler = "x" * max(0, scenario.page_bytes - 200)
    return (
        f"<html><body><h1>Page {index}</h1>"
        f"{''.join(links)}"
        '<script>fetch("/api/v1/items");</script>'
        f"<p>{filler}</p>"
        "</body></html>"
    )


def build_site(scenario: Scenario, base: str) -> tuple[dict[str, str], set[str]]:
    """Return ``(pages, failing_paths)`` for a scenario."""
    pages: dict[str, str] = {
        "/": "<html><body>"
        + "".join(
            f'<a href="{base}/p{index}">p{index}</a>'
            for index in range(min(ROOT_FANOUT, scenario.pages))
        )
        + "</body></html>"
    }
    failures: set[str] = set()

    for index in range(scenario.pages):
        path = f"/p{index}"
        pages[path] = build_page(index, scenario)
        if scenario.failure_every and index % scenario.failure_every == 0:
            failures.add(path)

    return pages, failures


class BenchHandler(BaseHTTPRequestHandler):
    """Serves the active scenario, tracking observed concurrency."""

    latency: ClassVar[float] = 0.0
    pages: ClassVar[dict[str, str]] = {}
    failures: ClassVar[set[str]] = set()
    lock: ClassVar[threading.Lock] = threading.Lock()
    active: ClassVar[int] = 0
    max_active: ClassVar[int] = 0
    requests: ClassVar[int] = 0

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        with BenchHandler.lock:
            BenchHandler.active += 1
            BenchHandler.max_active = max(BenchHandler.max_active, BenchHandler.active)
            BenchHandler.requests += 1
        try:
            if self.latency:
                time.sleep(self.latency)
            if path in BenchHandler.failures:
                # Simulate a dropped connection rather than a clean HTTP error.
                self.close_connection = True
                self.connection.close()
                return

            body = BenchHandler.pages.get(path, "<html><body>missing</body></html>")
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        finally:
            with BenchHandler.lock:
                BenchHandler.active -= 1

    def log_message(self, format: str, *args: object) -> None:
        pass


@dataclass
class RunResult:
    workers: int
    elapsed: float
    visited: int
    requests: int
    successes: int
    errors: int
    findings: int
    observed_concurrency: int


@dataclass
class LevelResult:
    workers: int
    runs: list[RunResult] = field(default_factory=list)

    @property
    def throughputs(self) -> list[float]:
        return [run.successes / max(run.elapsed, 1e-6) for run in self.runs]

    @property
    def best(self) -> RunResult:
        return min(self.runs, key=lambda run: run.elapsed)

    def summary(self) -> dict[str, float | int]:
        throughputs = self.throughputs
        best = self.best
        return {
            "workers": self.workers,
            "runs": len(self.runs),
            "pages_visited": best.visited,
            "requests": best.requests,
            "successes": best.successes,
            "errors": best.errors,
            "findings": best.findings,
            "observed_concurrency": best.observed_concurrency,
            "elapsed_best": round(best.elapsed, 4),
            "elapsed_median": round(statistics.median(run.elapsed for run in self.runs), 4),
            "throughput_best": round(max(throughputs), 2),
            "throughput_median": round(statistics.median(throughputs), 2),
            "throughput_min": round(min(throughputs), 2),
            "throughput_spread_pct": round(
                (max(throughputs) - min(throughputs)) / max(max(throughputs), 1e-6) * 100, 1
            ),
        }


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def machine_info() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "implementation": platform.python_implementation(),
    }


async def run_once(server_url: str, depth: int, workers: int) -> RunResult:
    with BenchHandler.lock:
        BenchHandler.active = 0
        BenchHandler.max_active = 0
        BenchHandler.requests = 0

    engine = Engine(server_url, depth=depth, workers=workers, persist=False)
    started = time.perf_counter()
    await engine.run()
    elapsed = time.perf_counter() - started

    return RunResult(
        workers=workers,
        elapsed=elapsed,
        visited=engine.pages_fetched,
        requests=engine.requests_made,
        successes=engine.successful_pages,
        errors=len(engine.errors),
        findings=len(engine.findings),
        observed_concurrency=BenchHandler.max_active,
    )


async def run_levels(
    base: str,
    depth: int,
    levels: list[int],
    runs: int,
) -> list[LevelResult]:
    results: list[LevelResult] = []
    for workers in levels:
        level = LevelResult(workers=workers)
        for run_index in range(runs):
            result = await run_once(base, depth, workers)
            level.runs.append(result)
            print(
                json.dumps(
                    {
                        "workers": workers,
                        "run": run_index + 1,
                        "elapsed": round(result.elapsed, 4),
                        "visited": result.visited,
                        "requests": result.requests,
                        "successes": result.successes,
                        "errors": result.errors,
                        "observed_concurrency": result.observed_concurrency,
                    }
                )
            )
        results.append(level)
    return results


def serve(scenario: Scenario, host: str, port: int) -> tuple[ThreadingHTTPServer, str, int]:
    base = f"http://{host}:{port}"
    pages, failures = build_site(scenario, base)
    BenchHandler.latency = scenario.latency
    BenchHandler.pages = pages
    BenchHandler.failures = failures
    httpd = ThreadingHTTPServer((host, port), BenchHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, base, len(pages)


def benchmark_scenario(
    scenario: Scenario,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    depth: int = 6,
    levels: list[int] | None = None,
    runs: int = DEFAULT_RUNS,
) -> list[LevelResult]:
    """Run one scenario end to end and return per-level measurements."""
    server_port = port or find_free_port()
    httpd, base, graph_size = serve(scenario, host, server_port)
    try:
        results = asyncio.run(run_levels(base, depth, levels or [1, 2, 4, 8], max(1, runs)))
    finally:
        httpd.shutdown()
        BenchHandler.pages = {}
        BenchHandler.failures = set()

    print(f"\n== scenario: {scenario.name} ==")
    print(
        f"graph_pages={graph_size} "
        f"latency_ms={scenario.latency_ms} "
        f"page_bytes={scenario.page_bytes} "
        f"failure_every={scenario.failure_every or 'none'} "
        f"runs={runs}"
    )
    for level in results:
        summary = level.summary()
        print(
            "workers={workers} visited={pages_visited} requests={requests} "
            "successes={successes} errors={errors} concurrency={observed_concurrency} "
            "throughput best/median/min={throughput_best}/{throughput_median}/{throughput_min} p/s "
            "spread={throughput_spread_pct}%".format(**summary)
        )
    return results


@click.command()
@click.option(
    "--scenario",
    default="low-latency",
    type=click.Choice([*SCENARIOS, "all"]),
    show_default=True,
    help="benchmark scenario to run",
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=0, type=int, help="0 picks a free port")
@click.option("--depth", default=6, type=int, show_default=True)
@click.option("--levels", default=DEFAULT_LEVELS, show_default=True)
@click.option("--runs", default=DEFAULT_RUNS, type=int, show_default=True)
def main(scenario: str, host: str, port: int, depth: int, levels: str, runs: int) -> None:
    """Benchmark the Pathscope crawler against reproducible local scenarios."""
    selected = list(SCENARIOS.values()) if scenario == "all" else [SCENARIOS[scenario]]
    level_list = [int(value) for value in levels.split(",") if value.strip()]

    print(json.dumps({"machine": machine_info()}))
    for item in selected:
        benchmark_scenario(
            item,
            host=host,
            port=port,
            depth=depth,
            levels=level_list,
            runs=runs,
        )
    print("\nNote: numbers are local-machine measurements; compare levels within a run.")


if __name__ == "__main__":
    main()
