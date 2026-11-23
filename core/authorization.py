"""Explicit authorization before a scan is allowed to start.

A discovery tool that runs against arbitrary hosts is easy to misuse. Pathscope
therefore refuses to start unless the operator states who authorized the scan,
or supplies a scope file that names an owner, a reference/ticket, the allowed
hosts, and (optionally) a validity window. ``--lab-mode`` is the deliberate,
recorded exception for a machine you own.

The authorization block is written into ``scan.json`` and the audit log so the
decision is auditable after the fact. It never contains credentials.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.exceptions import ConfigurationError
from core.security import canonical_host, hostname_of

_SCOPE_KEYS = frozenset(
    {"owner", "reference", "allowed_hosts", "not_before", "not_after", "description"}
)


@dataclass(frozen=True, slots=True)
class Authorization:
    """Who authorized this scan and which hosts it covers."""

    mode: str
    owner: str
    reference: str
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    not_before: datetime | None = None
    not_after: datetime | None = None
    source: str = ""

    def to_metadata(self) -> dict[str, Any]:
        """Return a JSON-safe record for scan metadata and the audit log."""
        return {
            "mode": self.mode,
            "owner": self.owner,
            "reference": self.reference,
            "allowed_hosts": list(self.allowed_hosts),
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "source": self.source,
        }


def _parse_timestamp(value: Any, *, key: str, source: Path) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(
            f"{source}: '{key}' must be an ISO-8601 timestamp",
            details={"path": str(source), "key": key},
        )
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigurationError(
            f"{source}: '{key}' is not a valid ISO-8601 timestamp",
            details={"path": str(source), "key": key},
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_host_entry(entry: Any, *, source: Path) -> str:
    if not isinstance(entry, str) or not entry.strip():
        raise ConfigurationError(
            f"{source}: every allowed host must be a non-empty string",
            details={"path": str(source)},
        )
    candidate = entry.strip()
    if candidate == "*":
        raise ConfigurationError(
            f"{source}: a wildcard host is not an authorization scope",
            details={"path": str(source)},
        )
    wildcard = candidate.startswith("*.")
    bare = candidate[2:] if wildcard else candidate
    canonical = canonical_host(bare)
    if not canonical:
        raise ConfigurationError(
            f"{source}: invalid allowed host {entry!r}",
            details={"path": str(source)},
        )
    return f"*.{canonical}" if wildcard else canonical


def load_scope_file(path: str | Path, *, now: datetime | None = None) -> Authorization:
    """Load and validate a scope file, including its validity window."""
    source = Path(path)
    if not source.is_file():
        raise ConfigurationError(f"Scope file not found: {source}", details={"path": str(source)})
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        raise ConfigurationError(
            "PyYAML is required to read a scope file", details={"path": str(source)}
        ) from None

    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigurationError(
            f"Scope file is not valid YAML: {exc}", details={"path": str(source)}
        ) from exc

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"{source}: scope file must be a mapping", details={"path": str(source)}
        )
    unknown = sorted(set(data) - _SCOPE_KEYS)
    if unknown:
        raise ConfigurationError(
            f"{source}: unknown scope keys: {', '.join(unknown)}",
            details={"path": str(source), "unknown": unknown},
        )

    owner = data.get("owner")
    reference = data.get("reference")
    if not isinstance(owner, str) or not owner.strip():
        raise ConfigurationError(f"{source}: 'owner' is required", details={"path": str(source)})
    if not isinstance(reference, str) or not reference.strip():
        raise ConfigurationError(
            f"{source}: 'reference' (ticket or approval) is required",
            details={"path": str(source)},
        )

    hosts = data.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ConfigurationError(
            f"{source}: 'allowed_hosts' must be a non-empty list",
            details={"path": str(source)},
        )
    allowed = tuple(_parse_host_entry(entry, source=source) for entry in hosts)

    not_before = _parse_timestamp(data.get("not_before"), key="not_before", source=source)
    not_after = _parse_timestamp(data.get("not_after"), key="not_after", source=source)
    if not_before and not_after and not_after <= not_before:
        raise ConfigurationError(
            f"{source}: 'not_after' must be later than 'not_before'",
            details={"path": str(source)},
        )

    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not_before and current < not_before:
        raise ConfigurationError(
            f"{source}: authorization is not valid before {not_before.isoformat()}",
            details={"path": str(source), "not_before": not_before.isoformat()},
        )
    if not_after and current > not_after:
        raise ConfigurationError(
            f"{source}: authorization expired at {not_after.isoformat()}",
            details={"path": str(source), "not_after": not_after.isoformat()},
        )

    return Authorization(
        mode="scope_file",
        owner=owner.strip(),
        reference=reference.strip(),
        allowed_hosts=allowed,
        not_before=not_before,
        not_after=not_after,
        source=str(source),
    )


def _host_covered(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    canonical = canonical_host(host)
    if not canonical:
        return False
    for entry in allowed_hosts:
        if entry.startswith("*."):
            suffix = entry[2:]
            if canonical.endswith("." + suffix):
                return True
        elif canonical == entry:
            return True
    return False


def resolve_authorization(
    *,
    target: str,
    authorized_by: str | None,
    scope_file: str | None,
    lab_mode: bool,
    now: datetime | None = None,
) -> Authorization:
    """Return the authorization for this scan or raise ``ConfigurationError``."""
    if lab_mode and scope_file:
        raise ConfigurationError("--lab-mode cannot be combined with --scope-file")
    if lab_mode and authorized_by:
        raise ConfigurationError("--lab-mode cannot be combined with --authorized-by")

    if lab_mode:
        return Authorization(
            mode="lab",
            owner="local operator",
            reference="lab-mode (no external authorization)",
            source="--lab-mode",
        )

    if scope_file:
        authorization = load_scope_file(scope_file, now=now)
        host = hostname_of(target)
        if not _host_covered(host, authorization.allowed_hosts):
            raise ConfigurationError(
                f"target {host or target!r} is not covered by {scope_file}: "
                f"{', '.join(authorization.allowed_hosts)}",
                details={"path": scope_file, "target_host": host},
            )
        return authorization

    if authorized_by and authorized_by.strip():
        return Authorization(
            mode="authorized_by",
            owner=authorized_by.strip(),
            reference=authorized_by.strip(),
            source="--authorized-by",
        )

    raise ConfigurationError(
        "authorization required: pass --authorized-by, --scope-file, or --lab-mode "
        "for a machine you own",
    )


def authorization_to_json(authorization: Authorization) -> str:
    """Return a stable JSON rendering, used for hashing and tests."""
    return json.dumps(authorization.to_metadata(), sort_keys=True)
