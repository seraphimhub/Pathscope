"""Terminal control characters, header injection, and output symlinks."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

from core.audit import AuditLog
from core.exceptions import ConfigurationError
from core.terminal import sanitize_terminal, validate_output_dir, validate_request_headers
from crawler.engine import Engine, _write_json_atomic


def test_terminal_escapes_are_removed_but_text_is_kept() -> None:
    hostile = "a\x1b[31mred\x1b[0m\r\nb\x1b]0;title\x07c\x08d\x00e\tf"
    cleaned = sanitize_terminal(hostile)
    assert "red" in cleaned
    assert "\x1b" not in cleaned
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\x07" not in cleaned
    assert "\x08" not in cleaned
    assert "\x00" not in cleaned
    assert "\t" not in cleaned
    assert cleaned == "aredbcdef"


def test_engine_errors_and_audit_never_contain_terminal_controls(tmp_path: Path) -> None:
    engine = Engine("http://example.com/", persist=True, output_dir=str(tmp_path))
    engine._start_audit()
    hostile_url = "http://example.com/\x1b[2J\x07"
    engine._record_error(hostile_url, ValueError("bad \x1b]0;pwned\x07\r\nInjected"))
    engine._audit_event("refused", url=hostile_url, reason="bad \x1b[31mred\x1b[0m")
    if engine._audit is not None:
        engine._audit.close()

    error = engine.errors[0]
    assert "\x1b" not in error["url"] and "\x07" not in error["url"]
    assert "\x1b" not in error["reason"] and "\r" not in error["reason"]
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "\x1b" not in raw and "\x07" not in raw and "\r" not in raw


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("X-Test", "ok\r\nInjected: yes"),
        ("X-Test", "ok\nInjected: yes"),
        ("X-Test", "ok\x00value"),
        ("Bad Name", "value"),
        ("", "value"),
    ],
)
def test_header_injection_is_rejected(name: str, value: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        validate_request_headers({name: value})
    assert "header" in str(excinfo.value).lower() or "control" in str(excinfo.value).lower()


def test_findings_are_sanitized_before_persistence() -> None:
    finding = Engine._redact_finding(
        {
            "type": "endpoint",
            "url": "http://example.com/\x1b[31m",
            "endpoint": "/api/\x1b]0;pwn\x07",
            "evidence": "/api/\x08value",
        }
    )
    assert "\x1b" not in finding["url"]
    assert "\x1b" not in finding["endpoint"]
    assert "\x07" not in finding["endpoint"]
    assert "\x08" not in finding["evidence"]


def test_engine_validates_headers_user_agent_and_scan_id() -> None:
    with pytest.raises(ConfigurationError):
        Engine("http://example.com/", headers={"X-Test": "a\r\nb"}, persist=False)
    with pytest.raises(ConfigurationError):
        Engine("http://example.com/", user_agent="bad\nagent", persist=False)
    with pytest.raises(ConfigurationError):
        Engine("http://example.com/", scan_id="bad\x1b[31m", persist=False)


def test_output_dir_traversal_and_symlink_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        validate_output_dir("../escape")
    with pytest.raises(ConfigurationError):
        validate_output_dir("a/../../escape")

    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ConfigurationError):
        validate_output_dir(str(link))


def test_audit_log_refuses_to_follow_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("original\n")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)

    audit = AuditLog(str(link))
    assert audit.failed is True
    audit.record("scan_start")
    audit.close()

    assert link.is_symlink()
    assert target.read_text() == "original\n"


def test_scan_continues_and_records_an_unavailable_audit_sink(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("original\n")
    (tmp_path / "audit.jsonl").symlink_to(target)

    engine = Engine(
        "http://127.0.0.1:1/",
        depth=0,
        timeout=1,
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["audit_error"]
    assert target.read_text() == "original\n"
    assert (tmp_path / "findings.json").is_file()


def test_json_output_replaces_a_symlink_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("original\n")
    link = tmp_path / "findings.json"
    link.symlink_to(target)

    _write_json_atomic(str(link), {"safe": True})

    assert target.read_text() == "original\n"
    assert not link.is_symlink()
    mode = stat.S_IMODE(link.stat().st_mode)
    assert mode == 0o600
    assert link.stat().st_uid == os.getuid()
    assert json.loads(link.read_text()) == {"safe": True}
