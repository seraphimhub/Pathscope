"""Discovery accuracy measured against an annotated ground-truth dataset.

The fixture files in ``tests/fixtures/discovery`` are the labelled dataset; the
expected sets below are its ground truth. Precision and recall are computed
from the real scanner output, so a change that starts reporting comments or
relative strings, or that drops a real endpoint, fails this test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners.endpoints import scan_endpoints
from scanners.secrets import scan_secrets

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"
JS_URL = "https://example.com/assets/app.js"
HTML_URL = "https://example.com/"

JS_ENDPOINTS = {
    "/api/v1/users",
    "/api/v1/posts",
    "/api/v2",
    "/invoices",
    "/api/v2/invoices",  # statically concatenated literals
    "https://api.example.com/v2/orders",
    "/search?q=1",
    "/static/app.js",
    "/api/v1/health",
}

JS_NOT_ENDPOINTS = {
    "/api/v1/commented-out",  # line comment
    "/api/v1/block-commented",  # block comment
    "/static/app.js.map",  # source map artefact
    "api/v1/relative",  # relative string, ambiguous without a base URL
    "not-a-path",
}

HTML_ENDPOINTS = {
    "/assets/site.css",
    "/assets/app.js",
    "/about",
    "/api/v1/users",
    "/img/logo.png",
    "/login",
    "/api/v1/health",
}

HTML_NOT_ENDPOINTS = {"/legacy/commented", "/api/v1/disabled"}

JS_SECRET_PATTERNS = {"api[_-]?key", "token", "password"}

# Values that must never appear in scanner output.
RAW_SECRET_VALUES = ("EXAMPLE_PLACEHOLDER_VALUE_123", "hunter2")


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def evaluate(found: set[str], expected: set[str]) -> tuple[float, float]:
    """Return ``(precision, recall)`` for a discovery run."""
    true_positives = len(found & expected)
    false_positives = len(found - expected)
    false_negatives = len(expected - found)

    precision = true_positives / (true_positives + false_positives) if found else 0.0
    recall = true_positives / (true_positives + false_negatives) if expected else 1.0
    return precision, recall


def test_javascript_endpoint_discovery_has_no_false_positives() -> None:
    findings = scan_endpoints(JS_URL, load("app.js"))
    found = {finding["endpoint"] for finding in findings}

    precision, recall = evaluate(found, JS_ENDPOINTS)

    assert found & JS_NOT_ENDPOINTS == set(), f"false positives: {found & JS_NOT_ENDPOINTS}"
    assert found == JS_ENDPOINTS, f"missing: {JS_ENDPOINTS - found}, extra: {found - JS_ENDPOINTS}"
    assert precision == pytest.approx(1.0)
    assert recall == pytest.approx(1.0)


def test_html_endpoint_discovery_has_no_false_positives() -> None:
    findings = scan_endpoints(HTML_URL, load("page.html"))
    found = {finding["endpoint"] for finding in findings}

    precision, recall = evaluate(found, HTML_ENDPOINTS)

    assert found & HTML_NOT_ENDPOINTS == set()
    assert precision == pytest.approx(1.0)
    assert recall == pytest.approx(1.0)


def test_duplicate_literals_are_reported_once() -> None:
    findings = scan_endpoints(JS_URL, load("app.js"))
    endpoints = [finding["endpoint"] for finding in findings]

    assert endpoints.count("/api/v1/users") == 1
    assert len(endpoints) == len(set(endpoints))


def test_fragment_is_not_part_of_an_endpoint() -> None:
    findings = scan_endpoints(HTML_URL, load("page.html"))
    endpoints = {finding["endpoint"] for finding in findings}

    assert "/about" in endpoints
    assert all("#" not in endpoint for endpoint in endpoints)


def test_every_endpoint_finding_is_located_and_categorised() -> None:
    for url, name in ((JS_URL, "app.js"), (HTML_URL, "page.html")):
        for finding in scan_endpoints(url, load(name)):
            assert finding["url"] == url
            assert finding["line"] >= 1
            assert finding["category"] in {"path", "absolute_url", "concatenated_path"}
            assert finding["evidence"]


def test_secret_pattern_recall_matches_ground_truth() -> None:
    findings = scan_secrets(JS_URL, load("app.js"))
    found = {finding["pattern"] for finding in findings}

    precision, recall = evaluate(found, JS_SECRET_PATTERNS)

    assert precision == pytest.approx(1.0)
    assert recall == pytest.approx(1.0)
    assert {finding["category"] for finding in findings} == {"api_key", "token", "password"}


def test_secret_findings_never_contain_the_value() -> None:
    findings = scan_secrets(JS_URL, load("app.js"))
    serialized = repr(findings)

    for value in RAW_SECRET_VALUES:
        assert value not in serialized

    for finding in findings:
        assert finding["evidence"].count("*") >= 8
        assert finding["line"] >= 1
        assert finding["count"] >= 1


def test_placeholder_and_documentation_tokens_are_not_called_credentials() -> None:
    """A pattern hit is not a verified credential; the finding must say so."""
    findings = scan_secrets(JS_URL, load("app.js"))

    assert findings
    for finding in findings:
        assert finding["type"] == "secret_pattern"
        # No verification was attempted, so no verification claim may exist.
        assert finding.get("verification_status") is None
        assert finding.get("verified") is None
