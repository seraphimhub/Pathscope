"""Endpoint discovery: path literals and absolute API URLs in page/JS content."""

from __future__ import annotations

import re
from typing import Any

# Quoted absolute paths: "/api/v1/users", '/health?deep=1'
_PATH_RE = re.compile(r"""["'](/(?!/)[^"'\s\\]*)["']""")

# Quoted absolute http(s) URLs: "https://api.example.com/v1/users"
_URL_RE = re.compile(r"""["'](https?://[^"'\s\\]+)["']""")

# Values that look like paths but are not endpoints.
_IGNORED_SUFFIXES = (".map", ".md")
_IGNORED_PREFIXES = ("/\\",)


def scan_endpoints(url: str, content: str) -> list[dict[str, Any]]:
    """Return de-duplicated endpoint findings found in ``content``.

    Every finding carries ``type``, the ``url`` of the page it was found on,
    the ``endpoint`` string, and the 1-based ``line`` of the first occurrence.
    Findings are pattern-presence based: no request is made, so nothing here is
    verified as live.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern, field_name in ((_PATH_RE, "endpoint"), (_URL_RE, "endpoint")):
        for match in pattern.finditer(content):
            endpoint = match.group(1)
            if not _is_reportable(endpoint) or endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append(
                {
                    "type": "endpoint",
                    "url": url,
                    field_name: endpoint,
                    "line": content.count("\n", 0, match.start()) + 1,
                }
            )

    return findings


def _is_reportable(endpoint: str) -> bool:
    if len(endpoint) < 2:
        return False
    if endpoint.startswith(_IGNORED_PREFIXES):
        return False
    return not endpoint.endswith(_IGNORED_SUFFIXES)
