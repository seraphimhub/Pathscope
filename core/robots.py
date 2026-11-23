"""Minimal robots.txt parser for the ``off``/``report``/``respect`` policy.

Only the ``*`` user-agent group is applied. Matching follows RFC 9309 closely
enough for crawling decisions: longest matching rule wins, ``Allow`` wins a
tie, ``*`` is a wildcard, and an empty ``Disallow`` means "allow everything".
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def _compile_rule(pattern: str) -> re.Pattern[str]:
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    expression = re.escape(body).replace(r"\*", ".*")
    return re.compile("^" + expression + ("$" if anchored else ""))


@dataclass(frozen=True, slots=True)
class RobotsRule:
    allow: bool
    pattern: str

    def matches(self, path: str) -> bool:
        return _compile_rule(self.pattern).match(path) is not None


@dataclass(frozen=True, slots=True)
class RobotsPolicy:
    """Parsed rules for one host."""

    rules: tuple[RobotsRule, ...] = ()
    source: str = ""

    @classmethod
    def parse(cls, text: str, *, user_agent: str = "*", source: str = "") -> RobotsPolicy:
        rules: list[RobotsRule] = []
        active = False
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "user-agent":
                active = value.lower() in {"*", user_agent.lower()}
            elif key in {"allow", "disallow"} and active:
                if key == "disallow" and value == "":
                    continue
                rules.append(RobotsRule(allow=key == "allow", pattern=value))
        return cls(rules=tuple(rules), source=source)

    def allows(self, path: str) -> bool:
        """Return True when ``path`` may be fetched under this policy."""
        if not path:
            path = "/"
        best: RobotsRule | None = None
        for rule in self.rules:
            if not rule.matches(path):
                continue
            if (
                best is None
                or len(rule.pattern) > len(best.pattern)
                or (len(rule.pattern) == len(best.pattern) and rule.allow)
            ):
                best = rule
        return True if best is None else best.allow
