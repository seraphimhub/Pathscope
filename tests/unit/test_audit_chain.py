"""The audit log is hash-chained and tampering is detectable."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.audit import AuditLog, verify_audit_file

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_entries_are_chained_and_verify_clean(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.record("scan_start", target="http://example.com/")
    audit.record("refused", url="http://example.com/private", reason="scope")
    audit.close()

    rows = entries(path)
    assert rows[0]["schema"] == "pathscope.audit.v1"
    assert rows[0]["prev_hash"] == ""
    assert rows[0]["hash"]
    assert rows[1]["prev_hash"] == rows[0]["hash"]

    result = verify_audit_file(path)
    assert result.valid is True
    assert result.entries == 2
    assert result.first_bad_line is None


def test_a_second_run_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    for marker in ("one", "two"):
        audit = AuditLog(str(path))
        audit.record("scan_start", target=marker)
        audit.close()

    rows = entries(path)
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert verify_audit_file(path).valid is True


def test_editing_a_middle_entry_reports_the_first_bad_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.record("scan_start", target="a")
    audit.record("scan_stop", target="b")
    audit.record("scan_start", target="c")
    audit.close()

    rows = entries(path)
    rows[1]["target"] = "tampered"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")

    result = verify_audit_file(path)
    assert result.valid is False
    assert result.first_bad_line == 2
    assert "hash" in result.reason.lower()


def test_a_broken_prev_link_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.record("scan_start")
    audit.record("scan_stop")
    audit.close()

    rows = entries(path)
    rows[1]["prev_hash"] = "0" * 64
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")

    result = verify_audit_file(path)
    assert result.valid is False
    assert result.first_bad_line == 2
    assert "previous" in result.reason.lower() or "prev" in result.reason.lower()


def test_malformed_json_reports_its_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.record("scan_start")
    audit.close()
    path.write_text(path.read_text() + "not json\n")
    result = verify_audit_file(path)
    assert result.valid is False
    assert result.first_bad_line == 2


def test_cli_audit_verify_reports_success_and_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.record("scan_start", target="a")
    audit.record("scan_stop", target="a")
    audit.close()

    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "."}
    good = subprocess.run(  # noqa: S603 - fixed argv, project-local entry point
        [sys.executable, "cli.py", "audit", "verify", str(path)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env=env,
        timeout=30,
    )
    assert good.returncode == 0, good.stdout + good.stderr
    assert "2 entries" in good.stdout

    rows = entries(path)
    rows[0]["target"] = "tampered"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")
    bad = subprocess.run(  # noqa: S603 - fixed argv, project-local entry point
        [sys.executable, "cli.py", "audit", "verify", str(path)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env=env,
        timeout=30,
    )
    assert bad.returncode == 1
    assert "line 1" in bad.stdout
