"""Configuration loading, validation, and target resolution helpers.

Resolution order is explicit: command-line values win over config-file values,
which win over built-in defaults. Config files are validated before use, and an
unsafe or malformed configuration fails loudly instead of being silently
ignored, because a scan that quietly runs with the wrong scope is worse than a
scan that refuses to start.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

from core.exceptions import ConfigurationError

SECRET_PATTERNS = [
    r"api[_-]?key",
    r"secret",
    r"token",
    r"jwt",
    r"authorization",
    r"password",
]

INT_OPTIONS: dict[str, tuple[int, int]] = {
    "depth": (0, 100),
    "workers": (1, 512),
    "max_pages": (1, 1_000_000),
    "max_redirects": (0, 50),
}

FLOAT_OPTIONS: dict[str, tuple[float, float]] = {
    "timeout": (0.1, 600.0),
}

BOOL_OPTIONS = frozenset({"secrets", "endpoints", "js", "block_private", "allow_scheme_downgrade"})

STR_OPTIONS = frozenset({"target", "headers", "cookie", "api", "auth", "output_dir"})

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def load_config_from_file(
    path: str | os.PathLike[str] | None,
    *,
    strict: bool = False,
) -> dict[str, Any] | None:
    """Return a config mapping for ``path``.

    With ``strict`` a missing file, unreadable YAML, missing parser or non
    mapping root raises ``ConfigurationError``. Without it the historical
    lenient behaviour (``None``) is preserved for callers that only probe for a
    target.
    """
    if not path:
        return None

    config_path = pathlib.Path(path)
    if not config_path.is_file():
        if strict:
            raise ConfigurationError(
                f"Config file not found: {config_path}", details={"path": str(config_path)}
            )
        return None

    try:
        import yaml
    except ImportError:
        if strict:
            raise ConfigurationError(
                "PyYAML is required to read config files", details={"path": str(config_path)}
            ) from None
        return None

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        if strict:
            raise ConfigurationError(
                f"Config file is not valid YAML: {exc}", details={"path": str(config_path)}
            ) from exc
        return None

    if data is None:
        return {}
    if not isinstance(data, dict):
        if strict:
            raise ConfigurationError(
                "Config file root must be a mapping", details={"path": str(config_path)}
            )
        return None
    return data  # type: ignore[return-value]


def resolve_target_from_args(config_path: str | None, *, env_target: str = "") -> str | None:
    """Resolve the first non-empty target from env, then the config file."""
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
    """Return validated options with config-file values layered over ``defaults``."""
    cfg = load_config_from_file(config_path, strict=True)
    return merge_cli_options(defaults, cfg or {})


def merge_cli_options(
    defaults: dict[str, Any],
    config_values: dict[str, Any] | None = None,
    explicit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge defaults < config file < explicitly passed CLI options, then validate."""
    merged = dict(defaults)

    for key, value in (config_values or {}).items():
        if key in merged and value is not None:
            merged[key] = value

    for key, value in (explicit or {}).items():
        if key in merged and value is not None:
            merged[key] = value

    return validate_scan_options(merged)


def validate_scan_options(options: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy of ``options`` or raise ``ConfigurationError``.

    Unknown keys are preserved untouched so forward-compatible configs do not
    break; every known key is type-checked and range-checked.
    """
    cleaned: dict[str, Any] = dict(options)

    for key, (low, high) in INT_OPTIONS.items():
        if key in cleaned and cleaned[key] is not None:
            cleaned[key] = _coerce_int(key, cleaned[key], low, high)

    for key, (low, high) in FLOAT_OPTIONS.items():
        if key in cleaned and cleaned[key] is not None:
            cleaned[key] = _coerce_float(key, cleaned[key], low, high)

    for key in BOOL_OPTIONS:
        if key in cleaned and cleaned[key] is not None:
            cleaned[key] = _coerce_bool(key, cleaned[key])

    for key in STR_OPTIONS:
        if key in cleaned and cleaned[key] is not None:
            cleaned[key] = _coerce_str(key, cleaned[key])

    if cleaned.get("output_dir") == "":
        raise ConfigurationError("output_dir must not be empty", details={"option": "output_dir"})

    return cleaned


def _coerce_int(key: str, value: Any, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise ConfigurationError(
            f"{key} must be an integer, not a boolean", details={"option": key}
        )
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        number = int(value.strip())
    else:
        raise ConfigurationError(
            f"{key} must be an integer", details={"option": key, "value": value}
        )

    if not low <= number <= high:
        raise ConfigurationError(
            f"{key} must be between {low} and {high}", details={"option": key, "value": number}
        )
    return number


def _coerce_float(key: str, value: Any, low: float, high: float) -> float:
    if isinstance(value, bool):
        raise ConfigurationError(f"{key} must be a number, not a boolean", details={"option": key})
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ConfigurationError(
            f"{key} must be a number", details={"option": key, "value": value}
        ) from None

    if not low <= number <= high:
        raise ConfigurationError(
            f"{key} must be between {low} and {high}", details={"option": key, "value": number}
        )
    return number


def _coerce_bool(key: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_VALUES:
            return True
        if lowered in _FALSE_VALUES:
            return False
    raise ConfigurationError(f"{key} must be a boolean", details={"option": key, "value": value})


def _coerce_str(key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(f"{key} must be a string", details={"option": key, "value": value})
    return value
