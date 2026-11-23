"""Secret-pattern detection.

The scanner reports *where* a keyword pattern occurs, never the value around
it. Evidence is the matched line with quoted literals and long unquoted values
replaced by ``*``, so a finding is safe to persist, log, and hand to a client
while still pointing an analyst at the line that needs review.

A match does not mean a credential is valid or live: nothing is verified and
nothing is ever used.
"""

from __future__ import annotations

import re
from typing import Any

from core.config import SECRET_PATTERNS

_COMPILED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (pattern, re.compile(pattern, re.IGNORECASE)) for pattern in SECRET_PATTERNS
)

_CATEGORY_BY_KEYWORD = {
    "api": "api_key",
    "secret": "secret",
    "token": "token",
    "jwt": "jwt",
    "authorization": "authorization",
    "password": "password",
}

_QUOTED_RE = re.compile(r"""(["'])([^"'\n]*)(\1)""")
_BARE_ASSIGNMENT_RE = re.compile(r"""(=\s*)([A-Za-z0-9_\-+/]{8,})""")
_EVIDENCE_LIMIT = 200


def scan_secrets(url: str, content: str) -> list[dict[str, Any]]:
    """Return one finding per matched keyword pattern in ``content``."""
    findings: list[dict[str, Any]] = []

    for pattern, compiled in _COMPILED:
        first = compiled.search(content)
        if first is None:
            continue

        line_number, line = _line_at(content, first.start())
        findings.append(
            {
                "type": "secret_pattern",
                "url": url,
                "pattern": pattern,
                "category": _category_for(pattern),
                "line": line_number,
                "count": len(compiled.findall(content)),
                "evidence": _mask_line(line),
            }
        )

    return findings


def _line_at(content: str, offset: int) -> tuple[int, str]:
    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset)
    if end == -1:
        end = len(content)
    return content.count("\n", 0, offset) + 1, content[start:end]


def _mask_line(line: str) -> str:
    """Return ``line`` with every value masked, truncated for storage."""
    masked = _QUOTED_RE.sub(lambda match: match.group(1) + "*" * 8 + match.group(3), line)
    masked = _BARE_ASSIGNMENT_RE.sub(lambda match: match.group(1) + "*" * 8, masked)
    return masked.strip()[:_EVIDENCE_LIMIT]


def _category_for(pattern: str) -> str:
    lowered = pattern.lower()
    for keyword, category in _CATEGORY_BY_KEYWORD.items():
        if keyword in lowered:
            return category
    return "generic"
