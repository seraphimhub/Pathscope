"""robots.txt parsing and matching for the off/report/respect policy."""

from __future__ import annotations

from core.robots import RobotsPolicy

TEXT = """
User-agent: *
Disallow: /private
Allow: /private/public
Disallow: /*.pdf$
Disallow: /search?q=

User-agent: otherbot
Disallow: /
"""


def test_disallowed_prefix_is_blocked() -> None:
    policy = RobotsPolicy.parse(TEXT)
    assert policy.allows("/private") is False
    assert policy.allows("/private/report") is False


def test_longest_allow_rule_wins() -> None:
    policy = RobotsPolicy.parse(TEXT)
    assert policy.allows("/private/public/page") is True


def test_wildcard_and_end_anchor_rules() -> None:
    policy = RobotsPolicy.parse(TEXT)
    assert policy.allows("/docs/file.pdf") is False
    assert policy.allows("/docs/file.pdf?download=1") is True
    assert policy.allows("/search") is True
    assert policy.allows("/search?q=secret") is False


def test_unmatched_paths_are_allowed() -> None:
    policy = RobotsPolicy.parse(TEXT)
    assert policy.allows("/") is True
    assert policy.allows("/api/v1/users") is True


def test_other_user_agent_groups_do_not_apply() -> None:
    policy = RobotsPolicy.parse(TEXT)
    # "Disallow: /" belongs to otherbot; the * group still governs Pathscope.
    assert policy.allows("/anything") is True


def test_empty_disallow_allows_everything() -> None:
    policy = RobotsPolicy.parse("User-agent: *\nDisallow:\n")
    assert policy.allows("/anything") is True
    assert policy.rules == ()


def test_comments_and_blank_lines_are_ignored() -> None:
    policy = RobotsPolicy.parse("# comment\n\nUser-agent: *  # all\nDisallow: /tmp  # no\n")
    assert policy.allows("/tmp/x") is False
