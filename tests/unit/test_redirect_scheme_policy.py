"""Redirect scheme downgrades must not carry session credentials in cleartext.

The fetcher follows redirects manually, one hop at a time, so every hop is a
fresh request that inherits the session headers (Authorization, Cookie). A
same-host ``https://`` -> ``http://`` redirect previously passed the host-scope
check and would have sent those headers over plaintext. These tests use a
recording fake session instead of TLS: the assertion is that the downgraded URL
is never requested at all, which is the only way to guarantee the header is
never sent.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.exceptions import FetchError
from crawler.fetcher import fetch_response

AUTH_HEADERS = {"Authorization": "Bearer test-token-not-real", "Cookie": "session=abc123"}


class _FakeContent:
    async def read(self, _size: int = -1) -> bytes:
        return b""


class _FakeResponse:
    def __init__(self, status: int, location: str | None = None) -> None:
        self.status = status
        self.headers = {"Content-Type": "text/html"}
        if location is not None:
            self.headers["Location"] = location
        self.content = _FakeContent()

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def read(self, _size: int = -1) -> bytes:
        return b""


class RecordingSession:
    """Minimal stand-in for ``aiohttp.ClientSession`` that records requests."""

    def __init__(self, location: str) -> None:
        self.headers = dict(AUTH_HEADERS)
        self.location = location
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, **_kwargs: Any) -> _FakeResponse:
        self.requests.append((url, dict(self.headers)))
        if not self.requests[1:]:
            return _FakeResponse(302, self.location)
        return _FakeResponse(200)


@pytest.mark.asyncio
async def test_https_to_http_downgrade_is_refused_by_default() -> None:
    session = RecordingSession("http://example.com/login")

    with pytest.raises(FetchError) as excinfo:
        await fetch_response(
            session,  # type: ignore[arg-type]
            "https://example.com/start",
        )

    assert "cleartext" in excinfo.value.reason
    assert [url for url, _ in session.requests] == ["https://example.com/start"]


@pytest.mark.asyncio
async def test_auth_headers_are_never_sent_to_a_downgraded_hop() -> None:
    session = RecordingSession("http://example.com/login")

    with pytest.raises(FetchError):
        await fetch_response(session, "https://example.com/start")  # type: ignore[arg-type]

    sent_urls = [url for url, _ in session.requests]
    assert "http://example.com/login" not in sent_urls
    assert all(url.startswith("https://") for url in sent_urls)
    # The header is configured on the session; it just never reaches plaintext.
    assert session.requests[0][1] == AUTH_HEADERS


@pytest.mark.asyncio
async def test_downgrade_can_be_opted_into_explicitly() -> None:
    session = RecordingSession("http://example.com/login")

    result = await fetch_response(
        session,  # type: ignore[arg-type]
        "https://example.com/start",
        allow_scheme_downgrade=True,
    )

    assert result.status == 200
    assert [url for url, _ in session.requests] == [
        "https://example.com/start",
        "http://example.com/login",
    ]


@pytest.mark.asyncio
async def test_upgrade_and_same_scheme_redirects_are_allowed() -> None:
    session = RecordingSession("https://example.com/secure")
    result = await fetch_response(session, "http://example.com/start")  # type: ignore[arg-type]
    assert result.status == 200
    assert result.redirects == ("https://example.com/secure",)


@pytest.mark.asyncio
async def test_non_http_redirect_target_is_refused() -> None:
    session = RecordingSession("file:///etc/passwd")

    with pytest.raises(FetchError) as excinfo:
        await fetch_response(session, "https://example.com/start")  # type: ignore[arg-type]

    assert "unsupported redirect scheme" in excinfo.value.reason
    assert len(session.requests) == 1


@pytest.mark.asyncio
async def test_protocol_relative_redirect_keeps_current_scheme() -> None:
    session = RecordingSession("//example.com/other")

    result = await fetch_response(session, "https://example.com/start")  # type: ignore[arg-type]

    assert result.status == 200
    assert [url for url, _ in session.requests] == [
        "https://example.com/start",
        "https://example.com/other",
    ]
