"""Tests for project configuration values and expected presence of core config."""

from core import config


def test_secret_patterns_are_defined_and_nonempty():
    patterns = config.SECRET_PATTERNS
    assert isinstance(patterns, (list, tuple))
    assert len(patterns) > 0
    for pat in patterns:
        assert isinstance(pat, str)


def test_secret_patterns_include_common_keywords():
    patterns = set(config.SECRET_PATTERNS)
    expected = {"api", "secret", "token", "jwt", "authorization", "password"}
    assert patterns & expected
