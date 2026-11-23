"""Shared data models for scan, findings, URL provenance, and verification status."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any, Self
from urllib.parse import urldefrag, urlparse


class FindingType(StrEnum):
    SECRET_PATTERN = "secret_pattern"  # nosec B105
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    HEADER = "header"
    TECHNOLOGY = "technology"
    ASSET = "asset"


class VerificationStatus(StrEnum):
    DISCOVERED = "discovered"
    REFERENCED = "referenced"
    REQUESTED = "requested"
    RESPONDED = "responded"
    VERIFIED = "verified"


class Confidence(int, Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(slots=True)
class Finding:
    id: str
    scan_id: str
    type: FindingType
    title: str
    target_url: str
    source_url: str
    evidence: str = ""
    confidence: Confidence = Confidence.MEDIUM
    discovery_method: str = "extraction"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: VerificationStatus = VerificationStatus.DISCOVERED
    severity: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type.value,
            "title": self.title,
            "target_url": self.target_url,
            "source_url": self.source_url,
            "evidence": self.evidence,
            "confidence": self.confidence.name,
            "discovery_method": self.discovery_method,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "severity": self.severity,
            "extra": self.extra,
        }

    def redacted(self) -> dict[str, Any]:
        """Return a copy with sensitive evidence values removed."""
        safe = dict(self.extra)
        for sensitive_key in ("secret_value", "token_value", "password_value", "api_key_value"):
            safe.pop(sensitive_key, None)
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type.value,
            "title": self.title,
            "target_url": self.target_url,
            "source_url": self.source_url,
            "evidence": self.evidence,
            "confidence": self.confidence.name,
            "discovery_method": self.discovery_method,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "severity": self.severity,
            "extra": safe,
        }


@dataclass(slots=True)
class DiscoveredUrl:
    url: str
    normalized: str
    host: str
    scheme: str
    path: str
    depth: int
    source_url: str
    discovery_method: str
    crawled: bool = False
    parent_url: str = ""

    @property
    def netloc(self) -> str:
        return self.host

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        depth: int,
        source_url: str,
        discovery_method: str,
        parent_url: str = "",
    ) -> Self:
        parsed = urlparse(url)
        normalized = normalize_url(url)
        return cls(
            url=url,
            normalized=normalized,
            host=parsed.netloc or "",
            scheme=parsed.scheme or "http",
            path=parsed.path or "/",
            depth=depth,
            source_url=source_url,
            discovery_method=discovery_method,
            parent_url=parent_url,
        )


def normalize_url(url: str) -> str:
    """Normalize a URL by stripping the fragment and ensuring a scheme/netloc/path."""
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or ""
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"
