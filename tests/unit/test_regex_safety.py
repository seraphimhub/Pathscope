"""Adversarial regex inputs stay within a hard time budget.

Every runtime regex is exercised with a long, hostile input. The threshold is
intentionally loose enough for a loaded CI runner but low enough to catch
super-linear backtracking (seconds or worse).
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.exceptions import PathscopeError
from core.redaction import (
    _ASSIGNMENT_RE,
    _AUTH_SCHEME_RE,
    _HEADER_LINE_RE,
    _USERINFO_RE,
    redact_text,
)
from core.robots import RobotsPolicy
from core.security import canonicalize_request_url, check_url
from crawler.parser import extract_links
from scanners.endpoints import _CONCAT_RE, _PATH_RE, _URL_RE, scan_endpoints
from scanners.secrets import _BARE_ASSIGNMENT_RE, _QUOTED_RE, scan_secrets

CORPUS = Path(__file__).resolve().parents[1] / "fuzz" / "corpus"
BUDGET = 1.0


def assert_fast(callable_) -> object:
    started = time.perf_counter()
    result = callable_()
    elapsed = time.perf_counter() - started
    assert elapsed < BUDGET, f"took {elapsed:.3f}s"
    return result


def test_redaction_patterns_are_linear_on_huge_lines() -> None:
    line = "Cookie: " + "a" * 250_000
    assert_fast(lambda: _HEADER_LINE_RE.sub("Cookie: [REDACTED]", line))
    assert_fast(lambda: _ASSIGNMENT_RE.sub("token=[REDACTED]", "token=" + "A" * 250_000))
    assert_fast(lambda: _AUTH_SCHEME_RE.sub("Bearer [REDACTED]", "Bearer " + "A" * 250_000))
    assert_fast(lambda: _USERINFO_RE.sub("https://", "https://" + "a" * 250_000 + "@example.com/"))
    assert_fast(lambda: redact_text("Authorization: Bearer " + "A" * 250_000))


def test_scanner_patterns_are_linear_on_pathological_quotes() -> None:
    assert_fast(lambda: list(_PATH_RE.finditer("'" + "/a" * 100_000)))
    assert_fast(lambda: list(_URL_RE.finditer("'" + "http://a" * 50_000)))
    assert_fast(lambda: list(_CONCAT_RE.finditer('"' + "/a" * 100_000 + '\\"')))
    assert_fast(lambda: list(_QUOTED_RE.finditer('"' + "a" * 250_000)))
    assert_fast(lambda: list(_BARE_ASSIGNMENT_RE.finditer("=" + "a" * 250_000)))


def test_robots_wildcards_do_not_backtrack_catastrophically() -> None:
    pattern = "/*" + "*a" * 60 + "$"
    policy = RobotsPolicy.parse(f"User-agent: *\nDisallow: {pattern}\n")
    path = "/" + "a" * 100_000 + "b"
    started = time.perf_counter()
    allowed = policy.allows(path)
    elapsed = time.perf_counter() - started
    assert allowed is False
    assert elapsed < BUDGET, f"robots match took {elapsed:.3f}s"


def test_robots_parser_caps_hostile_rule_counts() -> None:
    text = "\n".join("User-agent: *\nDisallow: /x" for _ in range(20_000))
    started = time.perf_counter()
    policy = RobotsPolicy.parse(text)
    elapsed = time.perf_counter() - started
    assert len(policy.rules) <= 2000
    assert elapsed < BUDGET


def test_seed_corpus_is_handled_without_exceptions() -> None:
    html = (CORPUS / "parser.html").read_text()
    links = extract_links(html, "http://example.com/", "example.com", max_links=50)
    assert len(links) <= 50
    assert all("evil.test" not in link for link in links)

    robots = RobotsPolicy.parse((CORPUS / "robots.txt").read_text())
    assert robots.allows("/public") is True
    assert robots.allows("/private") is False
    assert robots.allows("/private/ok") is True

    errors = (CORPUS / "errors.txt").read_text()
    cleaned = redact_text(errors)
    assert "password" not in cleaned
    assert "hunter2" not in cleaned
    assert "FAKE-TOKEN-EXAMPLE" not in cleaned

    for url in (CORPUS / "urls.txt").read_text().splitlines():
        with contextlib.suppress(PathscopeError):
            check_url(url)
        canonicalize_request_url(url)


@given(st.text(max_size=3000))
@settings(max_examples=40, deadline=None)
def test_parser_never_raises_on_arbitrary_text(text: str) -> None:
    links = extract_links(text, "http://example.com/", "example.com", max_links=25)
    assert len(links) <= 25


@given(st.text(max_size=3000))
@settings(max_examples=40, deadline=None)
def test_scanners_never_raise_and_bound_output(text: str) -> None:
    assert len(scan_endpoints("http://example.com/", text)) <= len(text) + 1
    assert len(scan_secrets("http://example.com/", text)) <= 6


@given(st.text(max_size=3000))
@settings(max_examples=40, deadline=None)
def test_robots_parser_never_raises_and_bounds_rules(text: str) -> None:
    policy = RobotsPolicy.parse(text)
    assert len(policy.rules) <= 2000
    assert isinstance(policy.allows("/"), bool)


@given(st.text(max_size=300))
@settings(max_examples=40, deadline=None)
def test_url_policy_raises_only_pathscope_errors(text: str) -> None:
    with contextlib.suppress(PathscopeError):
        check_url(text)
    canonicalize_request_url(text)


@pytest.mark.parametrize("text", ["", "\x00", "\x1b[31m", "a" * 5000])
def test_redaction_is_total(text: str) -> None:
    assert isinstance(redact_text(text), str)
