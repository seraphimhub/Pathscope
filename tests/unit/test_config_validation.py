"""Configuration loading, validation, and precedence tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from core.config import (
    load_cli_options_from_config,
    load_config_from_file,
    merge_cli_options,
    validate_scan_options,
)
from core.exceptions import ConfigurationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "pathscope.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_valid_config_is_loaded(tmp_path: Path) -> None:
    path = write_config(tmp_path, "target: https://example.com\ndepth: 3\nworkers: 4\n")
    cfg = load_config_from_file(path, strict=True)

    assert cfg == {"target": "https://example.com", "depth": 3, "workers": 4}


def test_missing_file_raises_when_strict(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_config_from_file(tmp_path / "absent.yaml", strict=True)


def test_missing_file_returns_none_when_lenient(tmp_path: Path) -> None:
    assert load_config_from_file(tmp_path / "absent.yaml") is None


def test_empty_config_is_an_empty_mapping(tmp_path: Path) -> None:
    path = write_config(tmp_path, "")
    assert load_config_from_file(path, strict=True) == {}


def test_malformed_yaml_raises_when_strict(tmp_path: Path) -> None:
    path = write_config(tmp_path, "target: [unclosed\n")
    with pytest.raises(ConfigurationError):
        load_config_from_file(path, strict=True)


def test_malformed_yaml_is_ignored_when_lenient(tmp_path: Path) -> None:
    path = write_config(tmp_path, "target: [unclosed\n")
    assert load_config_from_file(path) is None


def test_non_mapping_root_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "- one\n- two\n")
    with pytest.raises(ConfigurationError):
        load_config_from_file(path, strict=True)


def test_missing_config_path_raises_for_cli_options() -> None:
    with pytest.raises(ConfigurationError):
        load_cli_options_from_config("/definitely/not/here.yaml", defaults={"depth": 2})


# ---------------------------------------------------------------------------
# Option validation
# ---------------------------------------------------------------------------


def test_valid_options_pass_through() -> None:
    options = {"depth": 3, "workers": 4, "timeout": 5.5, "max_pages": 100, "secrets": "yes"}
    cleaned = validate_scan_options(options)

    assert cleaned["depth"] == 3
    assert cleaned["workers"] == 4
    assert cleaned["timeout"] == 5.5
    assert cleaned["secrets"] is True


def test_numeric_strings_are_coerced() -> None:
    cleaned = validate_scan_options({"depth": "4", "out_of_range_extra": "ignored"})
    assert cleaned["depth"] == 4


@pytest.mark.parametrize(
    "options",
    [
        {"depth": "abc"},
        {"depth": True},
        {"depth": -1},
        {"depth": 101},
        {"workers": 0},
        {"workers": 513},
        {"max_pages": 0},
        {"max_redirects": -1},
        {"max_redirects": 51},
        {"timeout": 0},
        {"timeout": 601},
        {"timeout": "nan"},
        {"secrets": "maybe"},
        {"output_dir": 123},
        {"output_dir": ""},
        {"target": 42},
    ],
)
def test_invalid_options_are_rejected(options: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        validate_scan_options(options)


def test_unknown_keys_are_preserved_for_forward_compatibility() -> None:
    cleaned = validate_scan_options({"depth": 2, "future_option": "value"})
    assert cleaned["future_option"] == "value"


# ---------------------------------------------------------------------------
# Precedence: default < config file < explicit CLI
# ---------------------------------------------------------------------------


def test_config_overrides_defaults() -> None:
    merged = merge_cli_options({"depth": 2, "workers": 8}, {"depth": 5})
    assert merged["depth"] == 5
    assert merged["workers"] == 8


def test_explicit_cli_overrides_config() -> None:
    merged = merge_cli_options({"depth": 2, "workers": 8}, {"depth": 5}, {"depth": 1})
    assert merged["depth"] == 1


def test_none_values_in_config_do_not_clobber_defaults() -> None:
    merged = merge_cli_options({"depth": 2}, {"depth": None})
    assert merged["depth"] == 2


def test_conflicting_security_setting_is_decided_explicitly() -> None:
    # An explicit --allow-private is the operator's decision and wins over the file.
    merged = merge_cli_options({"block_private": False}, {"block_private": True})
    assert merged["block_private"] is True

    overridden = merge_cli_options(
        {"block_private": False}, {"block_private": True}, {"block_private": False}
    )
    assert overridden["block_private"] is False


def test_scope_settings_from_config_are_validated() -> None:
    with pytest.raises(ConfigurationError):
        merge_cli_options({"depth": 2}, {"depth": 999})


def test_scheme_downgrade_opt_in_is_a_validated_boolean() -> None:
    merged = merge_cli_options(
        {"allow_scheme_downgrade": False},
        {"allow_scheme_downgrade": "yes"},
    )
    assert merged["allow_scheme_downgrade"] is True

    explicit = merge_cli_options(
        {"allow_scheme_downgrade": False},
        {"allow_scheme_downgrade": True},
        {"allow_scheme_downgrade": False},
    )
    assert explicit["allow_scheme_downgrade"] is False

    with pytest.raises(ConfigurationError):
        validate_scan_options({"allow_scheme_downgrade": "sometimes"})


# ---------------------------------------------------------------------------
# CLI behaviour on bad configuration
# ---------------------------------------------------------------------------


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, project-local entry point
        [sys.executable, "cli.py", *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "."},
        timeout=60,
    )


def test_cli_exits_with_error_on_malformed_config(tmp_path: Path) -> None:
    path = write_config(tmp_path, "depth: 999\n")
    result = run_cli("--target", "https://example.com", "--config", str(path), "--quiet")

    assert result.returncode == 2
    assert "Configuration error" in result.stdout


def test_cli_exits_with_error_on_missing_config(tmp_path: Path) -> None:
    result = run_cli(
        "--target", "https://example.com", "--config", str(tmp_path / "nope.yaml"), "--quiet"
    )

    assert result.returncode == 2
    assert "Configuration error" in result.stdout
