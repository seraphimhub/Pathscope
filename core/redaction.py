"""Redaction of credentials before anything is logged, stored, or reported.

Pathscope never needs a secret value to do its job, so values that could
identify a user or grant access are removed at the boundary instead of being
trusted to stay out of the output. Two sources are handled:

* URL userinfo (``https://user:pass@host/path``) is dropped entirely, because
  the host and path are the only parts a finding needs;
* header, cookie and token values are replaced in free-form text such as
  exception messages, which can echo a request line or a header value.

The functions here are deliberately conservative: over-redacting a log line is
acceptable, leaking a credential is not.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

# The lookbehind prevents the engine from retrying the scheme at every
# character of a long word (e.g. 250k 'A's), which made this pattern quadratic.
# Scheme length is capped at the RFC maximum we could ever need.
_USERINFO_RE = re.compile(
    r"(?<![\w+.-])(?P<scheme>[a-z][a-z0-9+.-]{0,31}://)(?P<userinfo>[^/\s?#@]+)@",
    re.IGNORECASE,
)

_HEADER_LINE_RE = re.compile(
    r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key"
    r"|x-auth-token|x-csrf-token|x-xsrf-token)\b(\s*[:=]\s*)([^\r\n]+)",
)

_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(bearer|basic|digest|negotiate)\s+[A-Za-z0-9._~+/=-]+",
)

_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|secret"""
    r"""|password|passwd|pwd)\b(\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&"']+)""",
)

# Query parameters are part of a URL finding/report, not just free-form text.
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|authorization"
    r"|auth|password|passwd|secret|token)=)([^&#\s]*)"
)


def redact_url(value: str) -> str:
    """Return ``value`` with any URL userinfo removed.

    Invalid URLs still lose their ``user:pass@`` part through the text
    fallback, so a malformed redirect target cannot smuggle credentials into
    an error record.
    """
    if not value:
        return value
    try:
        parsed = urlsplit(value)
        if parsed.netloc and "@" in parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parsed.port is not None:
                host = f"{host}:{parsed.port}"
            cleaned = urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))
            return _redact_query_secrets(cleaned)
    except ValueError:
        pass
    fallback = _USERINFO_RE.sub(lambda match: match.group("scheme"), value)
    return _redact_query_secrets(fallback)


def _redact_query_secrets(url: str) -> str:
    """Replace values of credential-like query parameters in ``url``."""
    return _QUERY_SECRET_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", url)


def redact_text(value: str) -> str:
    """Return free-form text with credential values replaced."""
    if not value:
        return value
    redacted = _USERINFO_RE.sub(lambda match: match.group("scheme"), value)
    redacted = _HEADER_LINE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )
    redacted = _AUTH_SCHEME_RE.sub(lambda match: f"{match.group(1)} {REDACTED}", redacted)
    redacted = _ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )
    return redacted


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` safe to persist or print."""
    safe: dict[str, str] = {}
    for name, value in headers.items():
        if name.strip().lower() in SENSITIVE_HEADERS:
            safe[name] = REDACTED
        else:
            safe[name] = redact_text(value)
    return safe
