"""Minimal robots.txt parser for the ``off``/``report``/``respect`` policy.

Only the ``*`` user-agent group is applied. Matching follows RFC 9309 closely
enough for crawling decisions: longest matching rule wins, ``Allow`` wins a
tie, ``*`` is a wildcard, and an empty ``Disallow`` means "allow everything".

Patterns come from the scanned host, i.e. from the attacker. They are matched
with a linear wildcard walk (no regular expressions) and both the rule count
and pattern length are capped, so a hostile robots.txt cannot trigger
catastrophic backtracking or unbounded memory.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_RULES = 2000
MAX_PATTERN_LENGTH = 2048
MAX_PATH_LENGTH = 8192


def _glob_match(pattern: str, text: str) -> bool:
    """Match ``*`` wildcards in linear-ish time using the classic two-pointer walk."""
    pattern_index = 0
    text_index = 0
    star_index = -1
    star_text_index = 0

    while text_index < len(text):
        if pattern_index < len(pattern) and pattern[pattern_index] == text[text_index]:
            pattern_index += 1
            text_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == "*":
            star_index = pattern_index
            star_text_index = text_index
            pattern_index += 1
        elif star_index != -1:
            pattern_index = star_index + 1
            star_text_index += 1
            text_index = star_text_index
        else:
            return False

    while pattern_index < len(pattern) and pattern[pattern_index] == "*":
        pattern_index += 1
    return pattern_index == len(pattern)


@dataclass(frozen=True, slots=True)
class RobotsRule:
    allow: bool
    pattern: str

    def matches(self, path: str) -> bool:
        anchored = self.pattern.endswith("$")
        pattern = self.pattern[:-1] if anchored else self.pattern + "*"
        return _glob_match(pattern, path)


@dataclass(frozen=True, slots=True)
class RobotsPolicy:
    """Parsed rules for one host."""

    rules: tuple[RobotsRule, ...] = ()
    source: str = ""

    @classmethod
    def parse(cls, text: str, *, user_agent: str = "*", source: str = "") -> RobotsPolicy:
        rules: list[RobotsRule] = []
        active = False
        remaining = MAX_RULES
        for raw_line in text.splitlines():
            if remaining <= 0:
                break
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
                if len(value) > MAX_PATTERN_LENGTH:
                    continue
                rules.append(RobotsRule(allow=key == "allow", pattern=value))
                remaining -= 1
        return cls(rules=tuple(rules), source=source)

    def allows(self, path: str) -> bool:
        """Return True when ``path`` may be fetched under this policy."""
        if not path:
            path = "/"
        path = path[:MAX_PATH_LENGTH]
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
