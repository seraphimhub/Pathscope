"""The authorization gate must refuse, record, and validate scope files."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.authorization import load_scope_file, resolve_authorization
from core.exceptions import ConfigurationError

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_scan_without_authorization_is_refused() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        resolve_authorization(
            target="https://example.com",
            authorized_by=None,
            scope_file=None,
            lab_mode=False,
        )
    assert "authorization required" in str(excinfo.value)


def test_authorized_by_is_recorded_verbatim() -> None:
    authorization = resolve_authorization(
        target="https://example.com",
        authorized_by="  AppSec / TICKET-42  ",
        scope_file=None,
        lab_mode=False,
    )
    assert authorization.mode == "authorized_by"
    assert authorization.owner == "AppSec / TICKET-42"
    assert authorization.to_metadata()["source"] == "--authorized-by"


def test_lab_mode_is_explicit_and_recorded() -> None:
    authorization = resolve_authorization(
        target="http://127.0.0.1:8080",
        authorized_by=None,
        scope_file=None,
        lab_mode=True,
    )
    assert authorization.mode == "lab"
    assert authorization.allowed_hosts == ()


def test_lab_mode_cannot_be_combined_with_scope_file(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path,
        "owner: me\nreference: T-1\nallowed_hosts: [example.com]\n",
    )
    with pytest.raises(ConfigurationError):
        resolve_authorization(
            target="https://example.com",
            authorized_by=None,
            scope_file=str(path),
            lab_mode=True,
        )


def test_valid_scope_file_is_loaded_and_enforced(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path,
        "\n".join(
            [
                "owner: Security Team",
                "reference: ENG-1234",
                "allowed_hosts:",
                "  - example.com",
                "  - '*.example.com'",
                f"not_before: {(NOW - timedelta(days=1)).isoformat()}",
                f"not_after: {(NOW + timedelta(days=1)).isoformat()}",
            ]
        ),
    )
    authorization = resolve_authorization(
        target="https://app.example.com/login",
        authorized_by=None,
        scope_file=str(path),
        lab_mode=False,
        now=NOW,
    )
    assert authorization.mode == "scope_file"
    assert authorization.reference == "ENG-1234"
    assert authorization.allowed_hosts == ("example.com", "*.example.com")


def test_scope_file_must_cover_the_target(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path,
        "owner: me\nreference: T-1\nallowed_hosts: [internal.example]\n",
    )
    with pytest.raises(ConfigurationError) as excinfo:
        resolve_authorization(
            target="https://public.example",
            authorized_by=None,
            scope_file=str(path),
            lab_mode=False,
            now=NOW,
        )
    assert "not covered" in str(excinfo.value)


def test_expired_scope_is_refused(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path,
        "owner: me\nreference: T-1\nallowed_hosts: [example.com]\n"
        f"not_after: {(NOW - timedelta(minutes=1)).isoformat()}\n",
    )
    with pytest.raises(ConfigurationError) as excinfo:
        load_scope_file(path, now=NOW)
    assert "expired" in str(excinfo.value)


def test_scope_not_yet_valid_is_refused(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path,
        "owner: me\nreference: T-1\nallowed_hosts: [example.com]\n"
        f"not_before: {(NOW + timedelta(hours=1)).isoformat()}\n",
    )
    with pytest.raises(ConfigurationError) as excinfo:
        load_scope_file(path, now=NOW)
    assert "not valid before" in str(excinfo.value)


def test_scope_file_rejects_missing_fields_and_unknown_keys(tmp_path: Path) -> None:
    cases = [
        "reference: T-1\nallowed_hosts: [example.com]\n",
        "owner: me\nallowed_hosts: [example.com]\n",
        "owner: me\nreference: T-1\n",
        "owner: me\nreference: T-1\nallowed_hosts: []\n",
        "owner: me\nreference: T-1\nallowed_hosts: ['*']\n",
        "owner: me\nreference: T-1\nallowed_hosts: [example.com]\nextra: nope\n",
        "owner: me\nreference: T-1\nallowed_hosts: [example.com]\nnot_after: tomorrow\n",
    ]
    for index, body in enumerate(cases):
        path = tmp_path / f"scope-{index}.yaml"
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_scope_file(path, now=NOW)


def test_scope_file_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_scope_file(tmp_path / "absent.yaml", now=NOW)


def test_authorized_until_is_recorded() -> None:
    authorization = resolve_authorization(
        target="https://example.com",
        authorized_by="AppSec",
        scope_file=None,
        lab_mode=False,
        authorized_until="2026-07-01T00:00:00Z",
        now=NOW,
    )
    assert authorization.not_after == datetime(2026, 7, 1, tzinfo=UTC)
    assert authorization.to_metadata()["not_after"] == "2026-07-01T00:00:00+00:00"


def test_expired_authorized_until_is_refused() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        resolve_authorization(
            target="https://example.com",
            authorized_by="AppSec",
            scope_file=None,
            lab_mode=False,
            authorized_until="2026-05-31T00:00:00Z",
            now=NOW,
        )
    assert "expired" in str(excinfo.value)


@pytest.mark.parametrize("value", ["tomorrow", "", "2026-13-01"])
def test_invalid_authorized_until_is_refused(value: str) -> None:
    with pytest.raises(ConfigurationError):
        resolve_authorization(
            target="https://example.com",
            authorized_by="AppSec",
            scope_file=None,
            lab_mode=False,
            authorized_until=value,
            now=NOW,
        )


def test_authorized_until_without_authorized_by_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        resolve_authorization(
            target="https://example.com",
            authorized_by=None,
            scope_file=None,
            lab_mode=True,
            authorized_until="2026-07-01T00:00:00Z",
            now=NOW,
        )
