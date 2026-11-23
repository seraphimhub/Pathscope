"""Smoke tests for the benchmark harness itself.

The full benchmark is a manual tool, but its measurement plumbing must not rot:
these tests run small scenarios and check that the reported numbers are
internally consistent.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

from benchmarks.bench_crawler import SCENARIOS, Scenario, benchmark_scenario


def run_scenario(scenario: Scenario, **kwargs: object):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        return benchmark_scenario(scenario, **kwargs)


def test_benchmark_reports_consistent_metrics() -> None:
    scenario = Scenario("test", pages=6, latency_ms=0)
    levels = run_scenario(scenario, depth=2, levels=[1, 4], runs=2)

    assert [level.workers for level in levels] == [1, 4]
    for level in levels:
        assert len(level.runs) == 2
        best = level.best
        assert best.elapsed > 0
        assert 0 < best.visited <= UNIVERSE_PAGES
        assert best.requests >= best.visited
        assert best.successes + best.errors <= best.requests + 1
        assert best.observed_concurrency <= level.workers


def test_benchmark_observes_more_concurrency_with_more_workers() -> None:
    scenario = Scenario("concurrency", pages=8, latency_ms=20)
    levels = run_scenario(scenario, depth=1, levels=[1, 8], runs=1)

    serial, parallel = levels
    assert serial.runs[0].observed_concurrency == 1
    assert parallel.runs[0].observed_concurrency > 1


def test_flaky_scenario_reports_transport_errors() -> None:
    scenario = Scenario("flaky-test", pages=8, latency_ms=0, failure_every=2)
    levels = run_scenario(scenario, depth=2, levels=[4], runs=1)

    assert levels[0].runs[0].errors >= 1


def test_every_scenario_builds_a_graph() -> None:
    for name, scenario in SCENARIOS.items():
        assert scenario.pages > 0, name
        assert scenario.latency_ms >= 0


UNIVERSE_PAGES = 7  # root page plus the six scenario pages


def test_duplicate_link_scenario_does_not_inflate_visits() -> None:
    scenario = Scenario("dup", pages=6, latency_ms=0, duplicate_links=8)
    levels = run_scenario(scenario, depth=2, levels=[4], runs=1)
    best = levels[0].best

    assert best.visited <= UNIVERSE_PAGES
    assert best.successes <= UNIVERSE_PAGES


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_names_are_stable(name: str) -> None:
    assert SCENARIOS[name].name == name
