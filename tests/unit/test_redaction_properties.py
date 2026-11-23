"""Property: a credential placed in a known sensitive context never survives.

Covered contexts: URL userinfo, Authorization/Cookie header lines, key=value
assignments (quoted and unquoted), URL-encoded values, unicode values, and
values in multi-line text. Not covered (and documented in THREAT_MODEL.md):
base64 or otherwise transformed secrets, secrets split across lines, and bare
secrets embedded in prose with no sensitive key.
"""

from __future__ import annotations

from urllib.parse import quote

from hypothesis import given, settings
from hypothesis import strategies as st

from core.redaction import redact_text, redact_url

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~%+/=-"
SECRET = st.text(alphabet=ALPHABET, min_size=1, max_size=40)
UNICODE_SECRET = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=20
)


@given(SECRET)
@settings(max_examples=80, deadline=None)
def test_authorization_header_never_leaks(secret: str) -> None:
    value = f"ZZ{secret}QQ"
    payload = f"Authorization: Bearer {value}\nnext line"
    cleaned = redact_text(payload)
    assert value not in cleaned
    assert "next line" in cleaned


@given(SECRET)
@settings(max_examples=80, deadline=None)
def test_cookie_header_never_leaks(secret: str) -> None:
    value = f"ZZ{secret}QQ"
    cleaned = redact_text(f"Cookie: session={value}; theme=dark")
    assert value not in cleaned


@given(SECRET)
@settings(max_examples=80, deadline=None)
def test_assignment_never_leaks(secret: str) -> None:
    value = f"ZZ{secret}QQ"
    assert value not in redact_text(f"token={value}&other=1")
    assert value not in redact_text(f'password="{value}"')


@given(SECRET)
@settings(max_examples=80, deadline=None)
def test_url_encoded_assignment_never_leaks(secret: str) -> None:
    encoded = quote(f"ZZ{secret}QQ", safe="")
    cleaned = redact_text(f"api_key={encoded}")
    assert encoded not in cleaned


@given(SECRET)
@settings(max_examples=80, deadline=None)
def test_url_userinfo_is_removed(secret: str) -> None:
    encoded = quote(f"ZZ{secret}QQ", safe="")
    cleaned = redact_url(f"https://user:{encoded}@example.com/path")
    assert encoded not in cleaned
    assert "example.com" in cleaned


@given(UNICODE_SECRET)
@settings(max_examples=80, deadline=None)
def test_unicode_secret_never_leaks(secret: str) -> None:
    value = f"ZZ{secret}QQ"
    cleaned = redact_text(f"token={value}")
    assert value not in cleaned


@given(SECRET)
@settings(max_examples=40, deadline=None)
def test_multiline_error_never_leaks(secret: str) -> None:
    value = f"ZZ{secret}QQ"
    payload = f"fetch failed\nCookie: a={value}\nretry"
    cleaned = redact_text(payload)
    assert value not in cleaned
    assert "fetch failed" in cleaned


def test_ordinary_text_is_not_over_redacted() -> None:
    text = "Scan complete: 3 pages, 2 endpoints, 0 errors."
    assert redact_text(text) == text
