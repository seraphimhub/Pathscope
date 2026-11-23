"""Scope and address-safety policy shared by the crawler and the CLI.

Pathscope is an authorized-scanning tool, so the default policy allows private
addresses (internal infrastructure is a legitimate target). The policy exists to
make the decision explicit and centralized:

* every URL must use http/https and carry a host
* a crawl may never leave its authorized host
* callers can refuse private/loopback/link-local/metadata targets on demand

Hostname resolution is intentionally *not* performed here. A DNS-based check
would add blocking I/O to the async crawl loop and still be racy (rebinding);
treat literal addresses and well-known local names as the enforceable layer.
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
    }
)


def hostname_of(url: str) -> str:
    """Return the lower-cased hostname of ``url`` (empty string when absent)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def netloc_of(url: str) -> str:
    """Return the lower-cased ``host:port`` netloc of ``url``."""
    try:
        return (urlparse(url).netloc or "").lower()
    except ValueError:
        return ""


def has_allowed_scheme(url: str) -> bool:
    """Return True when ``url`` uses an http/https scheme and has a host."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme.lower() in ALLOWED_SCHEMES and bool(parsed.hostname)


def is_private_host(host: str) -> bool:
    """Return True for loopback, private, link-local, reserved or local names.

    Anything that cannot be interpreted as an IP literal is treated as a
    regular hostname, except for the well-known local/metadata names above.
    """
    candidate = (host or "").strip().strip("[]").lower()
    if not candidate:
        return True
    if candidate in LOCAL_HOSTNAMES or candidate in METADATA_HOSTS:
        return True
    if candidate.endswith(".localhost") or candidate.endswith(".local"):
        return True

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not address.is_global


def host_in_scope(url: str, allowed_netloc: str, *, allow_subdomains: bool = False) -> bool:
    """Return True when ``url`` stays inside the authorized host scope."""
    candidate = netloc_of(url)
    allowed = (allowed_netloc or "").lower()
    if not candidate or not allowed:
        return False
    if candidate == allowed:
        return True
    if not allow_subdomains:
        return False

    allowed_host = hostname_of(f"//{allowed}")
    host = hostname_of(url)
    if not allowed_host or not host:
        return False
    # A subdomain relationship must not be satisfiable by a lookalike domain.
    return host.endswith("." + allowed_host)


def check_url(
    url: str,
    *,
    allowed_netloc: str | None = None,
    block_private: bool = False,
    allow_subdomains: bool = False,
) -> str:
    """Validate ``url`` against the scan policy and return it unchanged.

    Raises ``ScopeViolationError`` describing the first rule that fails.
    """
    if not has_allowed_scheme(url):
        raise ScopeViolationError(url, reason="unsupported scheme or missing host")

    host = hostname_of(url)
    if block_private and is_private_host(host):
        raise ScopeViolationError(
            url, allowed_host=allowed_netloc, reason="private address blocked"
        )

    if allowed_netloc and not host_in_scope(url, allowed_netloc, allow_subdomains=allow_subdomains):
        raise ScopeViolationError(
            url, allowed_host=allowed_netloc, reason="host outside allowed scope"
        )

    return url
