"""The CLI must refuse unauthorized scans and record the authorization it got."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TinyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        payload = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture()
def server() -> ThreadingHTTPServer:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), TinyHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, project-local entry point
        [sys.executable, "cli.py", *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": "."},
        timeout=60,
    )


def test_cli_refuses_to_scan_without_authorization() -> None:
    result = run_cli("--target", "https://example.com", "--quiet")

    assert result.returncode == 2
    assert "Authorization error" in result.stdout
    assert "authorization required" in result.stdout


def test_cli_refuses_lab_mode_combined_with_a_scope_file(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text("owner: me\nreference: T-1\nallowed_hosts: [example.com]\n")
    result = run_cli(
        "--target",
        "https://example.com",
        "--scope-file",
        str(scope),
        "--lab-mode",
        "--quiet",
    )
    assert result.returncode == 2
    assert "cannot be combined" in result.stdout


def test_cli_records_authorized_by_in_metadata(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/",
        "--authorized-by",
        "AppSec / TICKET-42",
        "--output-dir",
        str(tmp_path),
        "--depth",
        "0",
        "--quiet",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert metadata["authorization"]["mode"] == "authorized_by"
    assert metadata["authorization"]["owner"] == "AppSec / TICKET-42"
    assert (tmp_path / "audit.jsonl").is_file()
    assert metadata["user_agent"].startswith("Pathscope/")


def test_cli_accepts_lab_mode_and_records_it(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/",
        "--lab-mode",
        "--output-dir",
        str(tmp_path),
        "--depth",
        "0",
        "--scan-id",
        "lab-123",
        "--quiet",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert metadata["authorization"]["mode"] == "lab"
    assert metadata["scan_id"] == "lab-123"
