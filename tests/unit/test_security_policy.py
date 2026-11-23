"""Unit tests for the scope and address-safety policy."""

import pytest

from core.exceptions import ScopeViolationError
from core.security import (
    check_url,
    has_allowed_scheme,
    host_in_scope,
    is_private_host,
    netloc_of,
)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "[::1]",
        "10.0.0.5",
        "172.16.9.9",
        "192.168.1.10",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 - asserting this address is treated as non-global
        "localhost",
        "app.localhost",
        "printer.local",
        "",
    ],
)
def test_private_and_local_hosts_are_detected(host: str) -> None:
    assert is_private_host(host) is True


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "example.com", "api.example.com"])
def test_public_hosts_are_not_flagged(host: str) -> None:
    assert is_private_host(host) is False


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com:8080/x"])
def test_http_and_https_are_allowed(url: str) -> None:
    assert has_allowed_scheme(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,<h1>x</h1>",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "//example.com/no-scheme",
        "not a url",
        "",
    ],
)
def test_non_http_targets_are_rejected(url: str) -> None:
    assert has_allowed_scheme(url) is False


def test_netloc_is_lower_cased() -> None:
    assert netloc_of("HTTPS://Example.COM/Path") == "example.com"


def test_exact_host_is_in_scope() -> None:
    assert host_in_scope("https://example.com/a", "example.com") is True


def test_other_host_is_out_of_scope() -> None:
    assert host_in_scope("https://evil.com/a", "example.com") is False


def test_subdomains_are_out_of_scope_by_default() -> None:
    assert host_in_scope("https://admin.example.com/", "example.com") is False


def test_subdomains_can_be_opted_in() -> None:
    assert host_in_scope("https://admin.example.com/", "example.com", allow_subdomains=True) is True


def test_lookalike_domains_are_not_treated_as_subdomains() -> None:
    assert host_in_scope("https://notexample.com/", "example.com", allow_subdomains=True) is False


def test_port_must_match_scope() -> None:
    assert host_in_scope("https://example.com:8443/", "example.com") is False


def test_check_url_accepts_in_scope_target() -> None:
    url = "https://example.com/path"
    assert check_url(url, allowed_netloc="example.com") == url


def test_check_url_rejects_out_of_scope_host() -> None:
    with pytest.raises(ScopeViolationError) as excinfo:
        check_url("https://evil.com/", allowed_netloc="example.com")
    assert excinfo.value.details["reason"] == "host outside allowed scope"


def test_check_url_rejects_unsupported_scheme() -> None:
    with pytest.raises(ScopeViolationError):
        check_url("javascript:alert(1)")


def test_check_url_blocks_private_targets_when_requested() -> None:
    with pytest.raises(ScopeViolationError) as excinfo:
        check_url("http://127.0.0.1:8080/", block_private=True)
    assert excinfo.value.details["reason"] == "private address blocked"


def test_check_url_allows_private_targets_by_default() -> None:
    url = "http://127.0.0.1:8080/"
    assert check_url(url, allowed_netloc="127.0.0.1:8080") == url


def test_check_url_blocks_metadata_endpoint() -> None:
    with pytest.raises(ScopeViolationError):
        check_url("http://169.254.169.254/latest/meta-data/", block_private=True)
