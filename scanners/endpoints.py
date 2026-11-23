"""Endpoint discovery: path literals and absolute API URLs in page/JS content.

Only static, quoted literals are reported. Commented-out code is ignored so a
tutorial snippet does not become a finding, and ambiguous relative strings
("api/v1/users" without a leading slash) are deliberately *not* reported: their
meaning depends on a base URL Pathscope has not verified.

Every finding carries its source (``url``), location (``line``), ``category``
and the literal ``evidence`` it was extracted from. Nothing here verifies that
an endpoint is live.
"""

from __future__ import annotations

import re
from typing import Any

# Quoted absolute paths: "/api/v1/users", '/health?deep=1'
_PATH_RE = re.compile(r"""["'](/(?!/)[^"'\s\\]*)["']""")

# Quoted absolute http(s) URLs: "https://api.example.com/v1/users"
_URL_RE = re.compile(r"""["'](https?://[^"'\s\\]+)["']""")

# Statically concatenated literals: "/api" + "/v1/users"
_CONCAT_RE = re.compile(
    r"""(["'])(/[^"'\s\\]*)\1\s*\+\s*(["'])([^"'\s\\]*)\3""",
)

# Values that look like paths but are not endpoints.
_IGNORED_SUFFIXES = (".map", ".md")
_IGNORED_PREFIXES = ("/\\",)

CATEGORY_PATH = "path"
CATEGORY_ABSOLUTE_URL = "absolute_url"
CATEGORY_CONCATENATED = "concatenated_path"


def scan_endpoints(url: str, content: str) -> list[dict[str, Any]]:
    """Return de-duplicated endpoint findings found in ``content``."""
    if not content:
        return []

    masked = _mask_comments(content)
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for match in _PATH_RE.finditer(masked):
        _append(findings, seen, url, match.group(1), CATEGORY_PATH, match.start(), content)

    for match in _URL_RE.finditer(masked):
        _append(findings, seen, url, match.group(1), CATEGORY_ABSOLUTE_URL, match.start(), content)

    for match in _CONCAT_RE.finditer(masked):
        endpoint = match.group(2) + match.group(4)
        _append(findings, seen, url, endpoint, CATEGORY_CONCATENATED, match.start(), content)

    return findings


def _append(
    findings: list[dict[str, Any]],
    seen: set[str],
    url: str,
    endpoint: str,
    category: str,
    offset: int,
    content: str,
) -> None:
    # Fragments are never sent to the server, so they are not part of an endpoint.
    endpoint = endpoint.split("#", 1)[0]
    if not _is_reportable(endpoint) or endpoint in seen:
        return
    seen.add(endpoint)
    findings.append(
        {
            "type": "endpoint",
            "url": url,
            "endpoint": endpoint,
            "category": category,
            "evidence": endpoint,
            "line": content.count("\n", 0, offset) + 1,
        }
    )


def _is_reportable(endpoint: str) -> bool:
    if len(endpoint) < 2:
        return False
    if endpoint.startswith(_IGNORED_PREFIXES):
        return False
    return not endpoint.endswith(_IGNORED_SUFFIXES)


def _mask_comments(text: str) -> str:
    """Blank out comment spans while preserving offsets and newlines."""
    out = list(text)
    index = 0
    length = len(text)
    quote: str | None = None

    while index < length:
        char = text[index]

        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue

        if char in "\"'`":
            quote = char
            index += 1
            continue

        if text.startswith("<!--", index):
            index = _blank(out, index, _find_end(text, "-->", index + 4))
            continue

        if text.startswith("/*", index):
            index = _blank(out, index, _find_end(text, "*/", index + 2))
            continue

        if text.startswith("//", index) and _starts_line_comment(text, index):
            newline = text.find("\n", index)
            index = _blank(out, index, length if newline == -1 else newline)
            continue

        index += 1

    return "".join(out)


def _starts_line_comment(text: str, index: int) -> bool:
    """Distinguish ``// comment`` from a protocol-relative path inside markup."""
    if index == 0:
        return True
    previous = text[index - 1]
    return previous in " \t\n;(){}[],=:"


def _find_end(text: str, terminator: str, start: int) -> int:
    found = text.find(terminator, start)
    return len(text) if found == -1 else found + len(terminator)


def _blank(out: list[str], start: int, end: int) -> int:
    for position in range(start, min(end, len(out))):
        if out[position] != "\n":
            out[position] = " "
    return end
