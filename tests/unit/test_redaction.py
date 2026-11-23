"""Credential redaction must work on structured URLs and hostile error text."""

from __future__ import annotations

import pytest

from core.redaction import redact_headers, redact_text, redact_url


def test_url_userinfo_is_removed_entirely() -> None:
    assert redact_url("https://user:pass@example.com/a?b=1#frag") == (
        "https://example.com/a?b=1#frag"
    )
    assert redact_url("http://user@127.0.0.1:8080/x") == "http://127.0.0.1:8080/x"
    assert redact_url("https://[::1]:8443/x") == "https://[::1]:8443/x"


def test_url_without_userinfo_is_unchanged() -> None:
    url = "https://example.com/path?query=1"
    assert redact_url(url) == url


def test_malformed_url_still_loses_userinfo() -> None:
    redacted = redact_url("https://user:pass@example.com:notaport/x")
    assert "user" not in redacted
    assert "pass" not in redacted


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: Bearer abc123SECRET",
        "proxy-authorization=Basic dXNlcjpwYXNz",
        "Cookie: session=deadbeef; theme=dark",
        "Set-Cookie: sid=xyz; HttpOnly",
        "X-Api-Key: key-123456",
        "request failed with api_key=sk-live-abcdef",
        "token: eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "password='correct horse battery staple'",
    ],
)
def test_header_and_token_values_are_redacted(value: str) -> None:
    redacted = redact_text(value)
    for leaked in (
        "abc123SECRET",
        "dXNlcjpwYXNz",
        "deadbeef",
        "xyz",
        "key-123456",
        "sk-live-abcdef",
        "eyJhbGciOiJIUzI1NiJ9",
        "correct horse",
    ):
        assert leaked not in redacted


def test_crafted_error_string_with_multiple_credentials_is_clean() -> None:
    crafted = (
        "Fetch failed for https://user:topsecret@internal.example/x: "
        "Authorization: Bearer abc123; Cookie: session=deadbeef; "
        "redirect to https://svc:hunter2@other.example/"
    )
    redacted = redact_text(crafted)
    for leaked in ("topsecret", "abc123", "deadbeef", "hunter2", "user:", "svc:"):
        assert leaked not in redacted
    assert "internal.example" in redacted
    # The header rule redacts the rest of the line, which also removes any URL
    # that follows it; losing context is preferable to leaking a cookie.
    assert "other.example" not in redacted or "hunter2" not in redacted


def test_redaction_does_not_destroy_ordinary_text() -> None:
    value = "crawl reached /api/v1/users and then /about"
    assert redact_text(value) == value


def test_headers_are_redacted_by_name_not_only_by_shape() -> None:
    headers = {
        "Authorization": "Bearer abc",
        "Cookie": "session=1",
        "X-Api-Key": "k",
        "User-Agent": "Pathscope/0.1.0",
        "Referer": "https://user:pass@example.com/",
    }
    safe = redact_headers(headers)
    assert safe["Authorization"] == "[REDACTED]"
    assert safe["Cookie"] == "[REDACTED]"
    assert safe["X-Api-Key"] == "[REDACTED]"
    assert safe["User-Agent"] == "Pathscope/0.1.0"
    assert "pass" not in safe["Referer"]
