"""Console/log safety and operator-input validation.

A scanned page and an operator-supplied header are both untrusted text. Target
URLs can contain raw escape sequences, and headers with CR/LF can inject extra
request lines. Everything that reaches a terminal, a log record, an audit entry,
or a report goes through the sanitizers here.
"""

from __future__ import annotations

import os
import re
from pathlib import PurePath

from core.exceptions import ConfigurationError

# OSC sequences: ESC ] ... (BEL or ST)
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# CSI sequences: ESC [ parameters intermediate final
_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# Any remaining two-character escape.
_ESC_RE = re.compile(r"\x1b[@-_]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def sanitize_terminal(value: str) -> str:
    """Return ``value`` with terminal controls removed and text preserved."""
    if not value:
        return value
    cleaned = _OSC_RE.sub("", value)
    cleaned = _CSI_RE.sub("", cleaned)
    cleaned = _ESC_RE.sub("", cleaned)
    return _CONTROL_RE.sub("", cleaned)


def validate_header_value(name: str, value: str) -> None:
    """Raise when one header name/value could inject a second HTTP line."""
    if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
        raise ConfigurationError(
            "header name contains invalid characters",
            details={"header": name},
        )
    if not isinstance(value, str):
        raise ConfigurationError(
            "header value must be a string",
            details={"header": name},
        )
    if _CONTROL_RE.search(value):
        raise ConfigurationError(
            f"header {name!r} contains control characters (possible header injection)",
            details={"header": name},
        )


def validate_request_headers(headers: dict[str, str]) -> None:
    """Validate every request header, including case-insensitive duplicates."""
    seen: set[str] = set()
    for name, value in headers.items():
        validate_header_value(name, value)
        lowered = name.lower()
        if lowered in seen:
            raise ConfigurationError(
                f"duplicate header {name!r}",
                details={"header": name},
            )
        seen.add(lowered)


def validate_identity(value: str, *, option: str) -> None:
    """Reject controls in the User-Agent and scan-id header values."""
    if not isinstance(value, str):
        raise ConfigurationError(f"{option} must be a string", details={"option": option})
    if _CONTROL_RE.search(value):
        raise ConfigurationError(
            f"{option} contains control characters",
            details={"option": option},
        )


def validate_output_dir(path: str) -> str:
    """Refuse traversal and symlinked output directories.

    The filenames inside the directory are fixed, so the remaining operator
    input is the directory itself. A symlink would silently redirect every
    output file, including the audit log.
    """
    if not isinstance(path, str) or not path.strip():
        raise ConfigurationError("output_dir must not be empty", details={"option": "output_dir"})
    if _CONTROL_RE.search(path):
        raise ConfigurationError(
            "output_dir contains control characters", details={"option": "output_dir"}
        )
    if any(part == ".." for part in PurePath(path).parts):
        raise ConfigurationError(
            "output_dir traversal is not allowed", details={"option": "output_dir"}
        )
    if os.path.islink(path):
        raise ConfigurationError(
            "output_dir must not be a symlink", details={"option": "output_dir"}
        )
    if os.path.exists(path) and not os.path.isdir(path):
        raise ConfigurationError(
            "output_dir exists and is not a directory", details={"option": "output_dir"}
        )
    return path
