"""Legacy IPv4 spellings and userinfo must not defeat scope/address policy.

``inet_aton`` (and therefore ``getaddrinfo`` on glibc) accepts decimal, hex,
octal and shortened IPv4 forms. Python's ``ipaddress`` does not, so before this
regression suite those spellings were treated as ordinary hostnames and slipped
past the pre-flight policy check. The transport-level resolver still refused
them, but policy functions, redirect checks and scope comparison all disagreed
with the socket layer. These tests pin the two layers together.
"""

from __future__ import annotations

import pytest

from core.exceptions import ScopeViolationError
from core.resolver import SafeResolver
from core.security import (
    canonical_host,
    canonical_netloc,
    check_url,
    host_in_scope,
    is_private_host,
)
from crawler.engine import Engine

LOOPBACK_FORMS = {
    "2130706433": "127.0.0.1",  # 32-bit decimal
    "0x7f000001": "127.0.0.1",  # hex
    "017700000001": "127.0.0.1",  # octal with leading zero
    "127.1": "127.0.0.1",  # two-part shorthand
    "127.0.1": "127.0.0.1",  # three-part shorthand
    "0x7f.1": "127.0.0.1",  # mixed bases
}


def _url_for(host: str) -> str:
    if ":" in host:
        return f"http://[{host}]/"
    return f"http://{host}/"


NON_PUBLIC_HOSTS = [
    "2130706433",
    "0x7f000001",
    "017700000001",
    "127.1",
    "127.0.0.1.",
    "::ffff:127.0.0.1",
]


@pytest.mark.parametrize(("host", "canonical"), LOOPBACK_FORMS.items())
def test_legacy_numeric_forms_canonicalize_to_dotted_quad(host: str, canonical: str) -> None:
    assert canonical_host(host) == canonical


@pytest.mark.parametrize("host", NON_PUBLIC_HOSTS)
def test_legacy_numeric_forms_are_classified_as_private(host: str) -> None:
    assert is_private_host(host) is True


@pytest.mark.parametrize("host", NON_PUBLIC_HOSTS)
def test_block_private_refuses_legacy_numeric_forms(host: str) -> None:
    url = _url_for(host)
    with pytest.raises(ScopeViolationError) as excinfo:
        check_url(url, block_private=True)
    reason = excinfo.value.details.get("reason") or ""
    assert "blocked" in reason or "non-public" in reason, reason


@pytest.mark.parametrize("host", NON_PUBLIC_HOSTS)
def test_default_policy_still_allows_private_targets(host: str) -> None:
    url = _url_for(host)
    assert check_url(url) == url


def test_legacy_numeric_form_matches_scope_of_dotted_quad() -> None:
    assert host_in_scope("http://2130706433/", "127.0.0.1") is True
    assert host_in_scope("http://2130706433/", "example.com") is False


def test_mixed_numeric_form_cannot_escape_scope() -> None:
    # The numeric form resolves to 127.0.0.1, which is not example.com.
    with pytest.raises(ScopeViolationError):
        check_url(
            "http://0x7f000001/",
            allowed_netloc="example.com",
            block_private=True,
        )


def test_invalid_numeric_lookalike_stays_a_hostname() -> None:
    # Four parts but one is out of range: not an IP, so it must not be
    # silently reinterpreted as one.
    assert canonical_host("1.2.3.256") == "1.2.3.256"
    assert canonical_host("127.0.0.1.example.com") == "127.0.0.1.example.com"


def test_userinfo_in_start_url_does_not_define_scope() -> None:
    assert canonical_netloc("https://user:secret@127.0.0.1:8443/") == "127.0.0.1:8443"
    engine = Engine("https://user:secret@127.0.0.1:8443/", persist=False)
    assert engine.base_host == "127.0.0.1:8443"
    assert "secret" not in engine.base_host


def test_userinfo_in_redirect_cannot_widen_scope() -> None:
    assert host_in_scope("https://example.com@evil.test/", "example.com") is False
    with pytest.raises(ScopeViolationError):
        check_url("https://example.com@evil.test/", allowed_netloc="example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize("host", NON_PUBLIC_HOSTS)
async def test_safe_resolver_blocks_the_address_a_numeric_form_reaches(host: str) -> None:
    # Resolver output is injected so the test does not depend on the host OS's
    # getaddrinfo interpretation of numeric IPv4 spellings. Enforcement runs on
    # the answer that the connector would dial.
    resolver = SafeResolver(backing={host: ["127.0.0.1"]})
    try:
        with pytest.raises(ScopeViolationError) as excinfo:
            await resolver.resolve(host, 80)
    finally:
        await resolver.close()

    assert "non-public address" in (excinfo.value.details.get("reason") or "")


@pytest.mark.asyncio
async def test_safe_resolver_allows_private_answer_only_when_opted_in() -> None:
    resolver = SafeResolver(allow_private=True, backing={"2130706433": ["127.0.0.1"]})
    try:
        results = await resolver.resolve("2130706433", 80)
    finally:
        await resolver.close()

    assert [entry["host"] for entry in results] == ["127.0.0.1"]
