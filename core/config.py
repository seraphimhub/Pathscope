"""Configuration loading, validation, and target resolution helpers.

This module intentionally keeps the existing SECRET_PATTERNS constant and adds
the missing helpers referenced by the CLI.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

SECRET_PATTERNS = [
    r"api[_-]?key",
    r"secret",
    r"token",
    r"jwt",
    r"authorization",
    r"password",
]


def load_config_from_file(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Return a config dict for an existing YAML/JSON config file, or None."""
    p = pathlib.Path(path)
    if not p.is_file():
        return None

    try:
        import yaml
    except ImportError:
        return None

    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return None

    if not isinstance(data, dict):
        return None
    return data  # type: ignore[return-value]


def resolve_target_from_args(config_path: str | None, *, env_target: str = "") -> str | None:
    """Resolve the first non-empty target from CLI args, config, or env."""
    if env_target:
        return env_target
    if config_path:
        cfg = load_config_from_file(config_path)
        if isinstance(cfg, dict) and cfg.get("target"):
            return cfg["target"]
    return None


def load_cli_options_from_config(
    config_path: str | None, *, defaults: dict[str, Any]
) -> dict[str, Any]:
    """Return CLI option overrides from a config file on top of runtime defaults.

    This is the stable helper used by the CLI to merge config file values with
    the command-line defaults before resolving the final scan parameters.
    """
    cfg = load_config_from_file(config_path)
    if not isinstance(cfg, dict):
        return dict(defaults)

    merged: dict[str, Any] = dict(defaults)
    for key in (
        "target",
        "depth",
        "workers",
        "headers",
        "cookie",
        "api",
        "secrets",
        "endpoints",
        "js",
        "auth",
    ):
        if key in cfg and cfg[key] is not None:
            merged[key] = cfg[key]
    return merged
