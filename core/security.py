"""Scope and address-safety policy shared by every Pathscope component.

Pathscope is an authorized-scanning tool, so the default policy allows private
addresses (internal infrastructure is a legitimate target). The policy is still
enforced in one place:

* every URL must use http/https and carry a host
* a crawl may never leave its authorized host (exact match, subdomains opt-in)
* hostnames are compared after IDNA encoding, trailing-dot removal and default
  port normalization, so lookalike spellings cannot sneak past the check
* callers can refuse private/loopback/link-local/metadata targets, including
  hostnames that only *resolve* to such addresses (see ``core.resolver``)

Connection-level enforcement (DNS pinning) lives in ``core.resolver`` because it
needs the HTTP client's resolver interface.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from core.exceptions import ScopeViolationError

ALLOWED_SCHEMES = frozenset({"http", "https"})

LOCAL_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)

# Cloud metadata endpoints are never a valid scan target.
METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
    }
)

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical_host(host: str) -> str:
    """Return a comparable form of ``host``: lower-case, IDNA, no trailing dot.

    IPv6 literals are returned in compressed form without brackets.
    """
    candidate = (host or "").strip().strip("[]").rstrip(".")
    if not candidate:
        return ""

    candidate = candidate.lower()
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    try:
        return candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        # Unmappable names keep their raw form: they simply will not match a
        # scope entry, which fails closed.
        return candidate


def hostname_of(url: str) -> str:
    """Return the canonical hostname of ``url`` (empty string when absent)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return canonical_host(parsed.hostname or "")


def _parse_port(url: str) -> int | None:
    """Return the explicit port, or None. Raises ValueError for a bad port."""
    return urlparse(url).port


def canonical_netloc(url: str) -> str:
    """Return ``host[:port]`` in canonical form, dropping the default port.

    Returns an empty string when the URL has no usable host or port. Raises
    ``ValueError`` when the URL declares an invalid port.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""

    host = canonical_host(parsed.hostname or "")
    if not host:
        return ""

    port = parsed.port  # raises ValueError for invalid ports
    scheme = (parsed.scheme or "").lower()
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return _wrap_ipv6(host)
    return f"{_wrap_ipv6(host)}:{port}"


def netloc_of(url: str) -> str:
    """Return the canonical ``host[:port]`` of ``url`` (best effort, never raises)."""
    try:
        return canonical_netloc(url)
    except ValueError:
        return ""


def canonicalize_netloc(value: str) -> str:
    """Canonicalize a bare ``host`` or ``host:port`` string."""
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if candidate.startswith("["):
        # Already a bracketed IPv6 literal; append a dummy scheme for parsing.
        return canonical_netloc(f"//{candidate}")
    return canonical_netloc(f"//{candidate}")


def _wrap_ipv6(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{address.compressed}]" if address.version == 6 else host


def has_allowed_scheme(url: str) -> bool:
    """Return True when ``url`` uses an http/https scheme and has a host."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme.lower() in ALLOWED_SCHEMES and bool(parsed.hostname)


def is_global_address(address: str) -> bool:
    """Return True when ``address`` is a routable, non-special IP address.

    Rejects loopback, private, link-local, unspecified, multicast, reserved and
    IPv4-mapped IPv6 forms that point at any of those.
    """
    candidate = (address or "").strip().strip("[]")
    if not candidate:
        return False

    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        mapped = parsed.ipv4_mapped
        return mapped.is_global and not mapped.is_multicast

    if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local:
        return False
    if parsed.is_multicast or parsed.is_reserved:
        return False
    return parsed.is_global


def is_private_host(host: str) -> bool:
    """Return True for loopback, private, link-local, reserved or local names."""
    candidate = canonical_host(host)
    if not candidate:
        return True
    if candidate in LOCAL_HOSTNAMES or candidate in METADATA_HOSTS:
        return True
    if candidate.endswith(".localhost") or candidate.endswith(".local"):
        return True
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not is_global_address(candidate)


def host_in_scope(url: str, allowed_netloc: str, *, allow_subdomains: bool = False) -> bool:
    """Return True when ``url`` stays inside the authorized host scope."""
    try:
        candidate = canonical_netloc(url)
    except ValueError:
        return False
    if not candidate:
        return False

    try:
        allowed = canonicalize_netloc(allowed_netloc)
    except ValueError:
        return False
    if not allowed:
        return False
    if candidate == allowed:
        return True
    if not allow_subdomains:
        return False

    # Subdomain relations are only meaningful between hostnames, not IPs.
    candidate_host = hostname_of(url)
    allowed_host = canonical_host(allowed_netloc.split(":", 1)[0])
    if not candidate_host or not allowed_host:
        return False
    if _is_ip(candidate_host) or _is_ip(allowed_host):
        return False
    return candidate_host.endswith("." + allowed_host)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def check_url(
    url: str,
    *,
    allowed_netloc: str | None = None,
    block_private: bool = False,
    allow_subdomains: bool = False,
) -> str:
    """Validate ``url`` against the scan policy and return it unchanged.

    Raises ``ScopeViolationError`` describing the first rule that fails. DNS
    safety for hostnames cannot be decided here; use ``core.resolver`` so the
    addresses actually dialed are checked too.
    """
    if not has_allowed_scheme(url):
        raise ScopeViolationError(url, reason="unsupported scheme or missing host")

    try:
        netloc = canonical_netloc(url)
    except ValueError:
        raise ScopeViolationError(url, reason="invalid port in URL") from None
    if not netloc:
        raise ScopeViolationError(url, reason="unsupported scheme or missing host")

    host = hostname_of(url)
    if block_private:
        if _is_ip(host) and not is_global_address(host):
            raise ScopeViolationError(
                url, allowed_host=allowed_netloc, reason="private address blocked"
            )
        if is_private_host(host):
            raise ScopeViolationError(
                url, allowed_host=allowed_netloc, reason="private address blocked"
            )

    if allowed_netloc and not host_in_scope(url, allowed_netloc, allow_subdomains=allow_subdomains):
        raise ScopeViolationError(
            url, allowed_host=allowed_netloc, reason="host outside allowed scope"
        )

    return url
