"""Secret-pattern detection.

The scanner is deliberately conservative about what it emits: it reports *where*
a keyword pattern occurs, never the surrounding value. That keeps findings safe
to persist, log, and share with a client while still pointing an analyst at the
line that needs review.
"""

from __future__ import annotations

import re
from typing import Any

from core.config import SECRET_PATTERNS

_COMPILED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (pattern, re.compile(pattern, re.IGNORECASE)) for pattern in SECRET_PATTERNS
)


def scan_secrets(url: str, content: str) -> list[dict[str, Any]]:
    """Return one finding per matched keyword pattern in ``content``.

    Findings contain the page ``url``, the matched ``pattern``, the 1-based
    ``line`` of the first match, and the total ``count`` of matches. No matched
    value or surrounding snippet is included.
    """
    findings: list[dict[str, Any]] = []

    for pattern, compiled in _COMPILED:
        first = compiled.search(content)
        if first is None:
            continue
        findings.append(
            {
                "type": "secret_pattern",
                "url": url,
                "pattern": pattern,
                "line": content.count("\n", 0, first.start()) + 1,
                "count": len(compiled.findall(content)),
            }
        )

    return findings
