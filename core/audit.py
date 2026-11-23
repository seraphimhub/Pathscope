"""Tamper-evident, append-only audit trail for governance.

Each JSON line contains ``prev_hash`` (the previous line's hash) and ``hash``
over its own canonical payload, forming a chain. Editing a line, deleting one
line in the middle, or splicing two chains breaks the chain at the first bad
line. The chain does **not** detect deletion of the whole file or truncation of
the tail: an attacker with write access can remove every record. Treat the log
as evidence, not as an immutable ledger, and ship it somewhere else if that
matters.

The file is opened ``O_APPEND | O_NOFOLLOW`` with mode ``0600`` and verified to
be a regular file owned by the current user after opening.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.redaction import redact_text, redact_url
from core.terminal import sanitize_terminal

log = logging.getLogger("pathscope.audit")

AUDIT_SCHEMA = "pathscope.audit.v1"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def config_hash(config: dict[str, Any]) -> str:
    """Return a stable SHA-256 over the effective scan configuration."""
    payload = json.dumps(config, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _entry_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_string(value: str) -> str:
    return sanitize_terminal(redact_url(redact_text(value)))


def _safe_value(value: Any) -> Any:
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, dict):
        return {key: _safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    return value


def _read_last_hash(path: str) -> str:
    """Return the hash of the last complete line, or ``""``."""
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError:
        return ""
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return ""
        size = info.st_size
        if size <= 0:
            return ""
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            handle.seek(max(0, size - 1_048_576))
            tail = handle.read()
    except OSError:
        return ""
    finally:
        os.close(descriptor)

    for raw in reversed(tail.splitlines()):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ""
        if isinstance(entry, dict) and isinstance(entry.get("hash"), str):
            return str(entry["hash"])
        return ""
    return ""


@dataclass(slots=True)
class AuditVerification:
    """Outcome of verifying one audit file."""

    valid: bool
    entries: int
    first_bad_line: int | None = None
    reason: str = ""


def verify_audit_file(path: str | os.PathLike[str]) -> AuditVerification:
    """Verify every hash link and report the first broken line (1-based)."""
    expected_previous = ""
    entries = 0
    try:
        handle = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115
    except OSError as exc:
        return AuditVerification(False, 0, None, f"cannot read file: {exc}")

    try:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                return AuditVerification(False, entries, line_number, "blank line")
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return AuditVerification(False, entries, line_number, "malformed JSON")
            if not isinstance(entry, dict):
                return AuditVerification(False, entries, line_number, "entry is not an object")
            if entry.get("schema") != AUDIT_SCHEMA:
                return AuditVerification(
                    False, entries, line_number, "unsupported or missing schema"
                )
            claimed = entry.get("hash")
            previous = entry.get("prev_hash")
            if not isinstance(claimed, str) or not isinstance(previous, str):
                return AuditVerification(False, entries, line_number, "missing hash or prev_hash")
            if previous != expected_previous:
                return AuditVerification(
                    False,
                    entries,
                    line_number,
                    "previous hash does not match the previous entry",
                )
            payload = {key: value for key, value in entry.items() if key != "hash"}
            if _entry_hash(payload) != claimed:
                return AuditVerification(False, entries, line_number, "entry hash mismatch")
            expected_previous = claimed
            entries += 1
    finally:
        handle.close()

    return AuditVerification(True, entries)


class AuditLog:
    """Write-only, hash-chained JSON-lines audit log."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.failed = False
        self._previous_hash = _read_last_hash(path)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY | _NOFOLLOW,
                0o600,
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("audit log is not a regular file owned by the current user")
            os.fchmod(descriptor, 0o600)
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            self._descriptor = None
            self.failed = True
            log.warning("audit log unavailable at %s: %s", path, exc)
            return
        self._descriptor = descriptor

    def record(self, event: str, **fields: Any) -> None:
        """Append one chained event, redacting and sanitizing every string."""
        if self._descriptor is None:
            return
        safe: dict[str, Any] = {key: _safe_value(value) for key, value in fields.items()}
        payload: dict[str, Any] = {
            "schema": AUDIT_SCHEMA,
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            "prev_hash": self._previous_hash,
            **safe,
        }
        payload["hash"] = _entry_hash(payload)
        line = json.dumps(payload, sort_keys=True, default=str) + "\n"
        try:
            os.write(self._descriptor, line.encode("utf-8"))
        except OSError as exc:  # pragma: no cover - depends on the filesystem
            self.failed = True
            log.warning("audit log write failed: %s", exc)
            return
        self._previous_hash = payload["hash"]

    def close(self) -> None:
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            finally:
                self._descriptor = None
