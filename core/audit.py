"""Append-only structured audit trail for governance.

Every scan writes JSON lines for its start, stop, authorization decision, and
every request the policy refused. The file is opened ``O_APPEND`` with mode
``0600`` so an earlier record cannot be rewritten by a later run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from core.redaction import redact_text, redact_url

log = logging.getLogger("pathscope.audit")


def config_hash(config: dict[str, Any]) -> str:
    """Return a stable SHA-256 over the effective scan configuration."""
    payload = json.dumps(config, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditLog:
    """Write-only JSON-lines audit log."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.failed = False
        try:
            self._descriptor: int | None = os.open(
                path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
        except OSError as exc:  # pragma: no cover - depends on the filesystem
            self._descriptor = None
            self.failed = True
            log.warning("audit log unavailable at %s: %s", path, exc)

    def record(self, event: str, **fields: Any) -> None:
        """Append one event, redacting URLs and free-form messages."""
        if self._descriptor is None:
            return
        safe: dict[str, Any] = {}
        for key, value in fields.items():
            if isinstance(value, str):
                safe[key] = redact_url(redact_text(value))
            else:
                safe[key] = value
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **safe,
        }
        line = json.dumps(payload, sort_keys=True, default=str) + "\n"
        try:
            os.write(self._descriptor, line.encode("utf-8"))
        except OSError as exc:  # pragma: no cover - depends on the filesystem
            self.failed = True
            log.warning("audit log write failed: %s", exc)

    def close(self) -> None:
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            finally:
                self._descriptor = None
