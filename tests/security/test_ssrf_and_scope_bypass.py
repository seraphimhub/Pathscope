"""Security regression tests: scope bypasses and DNS-aware SSRF defence.

No test here touches a real metadata service or an internal network: every
hostname is either a policy input or resolved by a controlled resolver.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import aiohttp
import pytest

from core.exceptions import ScopeViolationError
from core.resolver import SafeResolver
from core.security import (
    canonical_netloc,
    check_url,
    host_in_scope,
    is_global_address,
)
from crawler.engine import Engine


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CountingHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []
    lock: ClassVar[threading.Lock] = threading.Lock()

    def do_GET(self) -> None:
        with CountingHandler.lock:
            CountingHandler.hits.append(self.path)
        payload = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def counting_server() -> ThreadingHTTPServer:
    CountingHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), CountingHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.20.5.5",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 - asserted to be non-public, never bound
        "::",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "224.0.0.1",
        "ff02::1",
    ],
)
def test_non_public_addresses_are_rejected(address: str) -> None:
    assert is_global_address(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_are_accepted(address: str) -> None:
    assert is_global_address(address) is True


def test_ipv4_mapped_public_address_is_allowed() -> None:
    assert is_global_address("::ffff:8.8.8.8") is True


# ---------------------------------------------------------------------------
# Host canonicalization / scope bypasses
# ---------------------------------------------------------------------------


def test_trailing_dot_and_case_are_normalized() -> None:
    assert host_in_scope("https://Example.COM./path", "example.com") is True


def test_default_port_is_normalized_but_explicit_other_port_is_not() -> None:
    assert host_in_scope("https://example.com:443/", "example.com") is True
    assert host_in_scope("https://example.com:8443/", "example.com") is False


def test_userinfo_cannot_be_used_to_spoof_the_host() -> None:
    # hostname is evil.com; example.com appears only as userinfo
    assert host_in_scope("https://example.com@evil.com/", "example.com") is False
    assert host_in_scope("https://evil.com@example.com/", "example.com") is True


def test_lookalike_domains_never_match() -> None:
    for candidate in (
        "https://example.com.evil.com/",
        "https://notexample.com/",
        "https://example.co/",
        "https://example.comm/",
    ):
        assert host_in_scope(candidate, "example.com", allow_subdomains=True) is False


def test_idna_hostnames_compare_after_encoding() -> None:
    assert host_in_scope("https://exämple.com/", "xn--exmple-cua.com") is True
    assert host_in_scope("https://xn--exmple-cua.com/", "xn--exmple-cua.com") is True


def test_percent_encoded_hostname_is_not_silently_decoded() -> None:
    assert host_in_scope("https://%65xample.com/", "example.com") is False


def test_dot_segments_do_not_escape_scope() -> None:
    url = "https://example.com/a/../../b"
    assert host_in_scope(url, "example.com") is True
    assert check_url(url, allowed_netloc="example.com") == url


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,x",
        "//example.com/no-scheme",
        "https:///no-host",
    ],
)
def test_non_http_targets_are_rejected(url: str) -> None:
    with pytest.raises(ScopeViolationError):
        check_url(url, allowed_netloc="example.com")


def test_invalid_port_is_rejected() -> None:
    with pytest.raises(ScopeViolationError) as excinfo:
        check_url("https://example.com:notaport/", allowed_netloc="example.com")
    assert "port" in excinfo.value.details["reason"]


def test_ipv6_literals_are_handled() -> None:
    assert canonical_netloc("http://[::1]:8080/") == "[::1]:8080"
    with pytest.raises(ScopeViolationError):
        check_url("http://[::1]:8080/", block_private=True)
    with pytest.raises(ScopeViolationError):
        check_url("http://[::ffff:127.0.0.1]/", block_private=True)


def test_private_policy_does_not_replace_scope_policy() -> None:
    # Allow-private must still not permit leaving the authorized host.
    with pytest.raises(ScopeViolationError) as excinfo:
        check_url("http://93.184.216.34/", allowed_netloc="example.com", block_private=False)
    assert excinfo.value.details["reason"] == "host outside allowed scope"


# ---------------------------------------------------------------------------
# Resolver-level enforcement (DNS rebinding / TOCTOU)
# ---------------------------------------------------------------------------


def test_resolver_rejects_hostname_resolving_to_loopback() -> None:
    resolver = SafeResolver(backing={"internal.test": ["127.0.0.1"]})
    with pytest.raises(ScopeViolationError) as excinfo:
        asyncio.run(resolver.resolve("internal.test", 80))
    assert "non-public" in excinfo.value.details["reason"]


def test_resolver_rejects_when_any_address_is_private() -> None:
    resolver = SafeResolver(backing={"mixed.test": ["93.184.216.34", "10.0.0.7"]})
    with pytest.raises(ScopeViolationError):
        asyncio.run(resolver.resolve("mixed.test", 443))


def test_resolver_rejects_metadata_and_ipv4_mapped_answers() -> None:
    resolver = SafeResolver(
        backing={
            "metadata.test": ["169.254.169.254"],
            "mapped.test": ["::ffff:127.0.0.1"],
        }
    )
    with pytest.raises(ScopeViolationError):
        asyncio.run(resolver.resolve("metadata.test", 80))
    with pytest.raises(ScopeViolationError):
        asyncio.run(resolver.resolve("mapped.test", 80))


def test_resolver_rejects_empty_answers() -> None:
    resolver = SafeResolver(backing={})
    with pytest.raises(ScopeViolationError) as excinfo:
        asyncio.run(resolver.resolve("nothing.test", 80))
    assert "did not resolve" in excinfo.value.details["reason"]


def test_resolver_allows_public_answers() -> None:
    resolver = SafeResolver(backing={"public.test": ["93.184.216.34"]})
    results = asyncio.run(resolver.resolve("public.test", 443))
    assert results[0]["host"] == "93.184.216.34"


def test_resolver_can_allow_private_when_policy_expects_it() -> None:
    resolver = SafeResolver(allow_private=True, backing={"internal.test": ["127.0.0.1"]})
    results = asyncio.run(resolver.resolve("internal.test", 80))
    assert results[0]["host"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_connector_refuses_dns_answer_pointing_at_private_address(
    counting_server: ThreadingHTTPServer,
) -> None:
    """The resolver is consulted *by the connector*, so a private answer never connects."""
    CountingHandler.hits = []
    port = counting_server.server_port
    resolver = SafeResolver(backing={"internal.test": ["127.0.0.1"]})
    connector = aiohttp.TCPConnector(resolver=resolver, ttl_dns_cache=0)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            with pytest.raises(ScopeViolationError) as excinfo:
                async with session.get(f"http://internal.test:{port}/private") as response:
                    await response.read()
    finally:
        await resolver.close()

    assert "non-public address" in excinfo.value.details["reason"]
    assert CountingHandler.hits == []


@pytest.mark.asyncio
async def test_connector_uses_the_validated_answer_when_private_is_allowed(
    counting_server: ThreadingHTTPServer,
) -> None:
    """Proves the connector dials the resolver's answer, not a second DNS lookup."""
    CountingHandler.hits = []
    port = counting_server.server_port
    resolver = SafeResolver(allow_private=True, backing={"internal.test": ["127.0.0.1"]})
    connector = aiohttp.TCPConnector(resolver=resolver, ttl_dns_cache=0)

    try:
        async with (
            aiohttp.ClientSession(connector=connector) as session,
            session.get(f"http://internal.test:{port}/allowed") as response,
        ):
            assert response.status == 200
    finally:
        await resolver.close()

    assert CountingHandler.hits == ["/allowed"]


# ---------------------------------------------------------------------------
# Redirect scope enforcement
# ---------------------------------------------------------------------------


class RedirectBypassHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            payload = (
                b"<html><body>"
                b'<a href="/cross-port">cross-port</a>'
                b'<a href="/cross-scheme">cross-scheme</a>'
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/cross-port":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port + 1}/admin")
            self.end_headers()
        elif self.path == "/cross-scheme":
            self.send_response(302)
            self.send_header("Location", "https://127.0.0.1/secure")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


def test_redirects_cannot_change_port_or_scheme() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), RedirectBypassHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{httpd.server_port}"
        engine = Engine(base + "/", depth=1, workers=2, persist=False)
        asyncio.run(engine.run())

        assert all("127.0.0.1:0" not in url for url in engine.visited)
        assert all(not url.startswith("https://") for url in engine.visited)
        reasons = " ".join(error["reason"] for error in engine.errors)
        assert "redirect target rejected" in reasons
        assert engine.findings is not None
    finally:
        httpd.shutdown()
