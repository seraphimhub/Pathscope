from __future__ import annotations

from typing import Any


class PathscopeError(Exception):
    """Base error for all Pathscope runtime failures."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class ConfigurationError(PathscopeError):
    """Raised when runtime configuration is invalid."""


class ScopeViolationError(PathscopeError):
    """Raised when a requested URL escapes the authorized target scope."""

    def __init__(
        self,
        url: str,
        *,
        allowed_host: str | None = None,
        reason: str = "out of scope",
    ) -> None:
        self.url = url
        self.allowed_host = allowed_host
        self.reason = reason
        super().__init__(
            f"Scope violation for {url}: {reason}",
            details={"url": url, "allowed_host": allowed_host, "reason": reason},
        )


class FetchError(PathscopeError):
    """Raised when HTTP fetch did not return usable content."""

    def __init__(self, url: str, *, reason: str | None = None) -> None:
        self.url = url
        self.reason = reason or "fetch failed"
        super().__init__(
            f"Fetch failed for {url}: {self.reason}", details={"url": url, "reason": self.reason}
        )


class ScannerError(PathscopeError):
    """Raised when a scanner plugin fails."""

    def __init__(
        self, message: str, *, plugin_id: str = "unknown", details: dict[str, Any] | None = None
    ) -> None:
        self.plugin_id = plugin_id
        super().__init__(message, details={"plugin_id": plugin_id, **(details or {})})


class EngineError(PathscopeError):
    """Raised when the crawl engine encounters a fatal lifecycle error."""


class StorageError(PathscopeError):
    """Raised when scan persistence fails."""
