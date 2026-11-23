"""CLI validation for hostile operator input and Phase 2 budgets."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CERT = PROJECT_ROOT / "tests" / "fixtures" / "tls" / "cert.pem"
KEY = PROJECT_ROOT / "tests" / "fixtures" / "tls" / "key.pem"


class Handler(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self) -> None:
        Handler.hits += 1
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
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
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


def test_expired_authorized_until_is_refused() -> None:
    result = run_cli(
        "--target",
        "https://example.com",
        "--authorized-by",
        "AppSec",
        "--authorized-until",
        "2020-01-01T00:00:00Z",
        "--quiet",
    )
    assert result.returncode == 2
    assert "Authorization error" in result.stdout
    assert "expired" in result.stdout


def test_missing_authorized_until_warns_loudly(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/",
        "--authorized-by",
        "AppSec",
        "--depth",
        "0",
        "--output-dir",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "without --authorized-until" in result.stdout


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--headers", '{"X-Test":"ok\\r\\nInjected: yes"}'),
        ("--cookie", "session=ok\nInjected=yes"),
        ("--user-agent", "Pathscope\r\nInjected: yes"),
        ("--scan-id", "id\x1b[31mvalue"),
    ],
)
def test_control_characters_in_operator_input_are_refused(flag: str, value: str) -> None:
    result = run_cli(
        "--target",
        "https://example.com",
        "--lab-mode",
        flag,
        value,
        "--quiet",
    )
    assert result.returncode == 2
    assert "control" in result.stdout.lower() or "header" in result.stdout.lower()


def test_console_never_prints_a_hostile_target_escape(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/\x1b[31mred\x07",
        "--lab-mode",
        "--json",
        "--depth",
        "0",
        "--output-dir",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "\x1b" not in result.stdout
    assert "\x07" not in result.stdout
    assert "\x1b" not in result.stderr


def test_output_dir_traversal_is_refused() -> None:
    result = run_cli(
        "--target",
        "https://example.com",
        "--lab-mode",
        "--output-dir",
        "../escape",
        "--quiet",
    )
    assert result.returncode == 2
    assert "traversal" in result.stdout.lower() or "output" in result.stdout.lower()


def test_insecure_warning_and_metadata(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/",
        "--lab-mode",
        "--insecure",
        "--depth",
        "0",
        "--output-dir",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "TLS certificate verification is disabled" in result.stdout
    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["tls"]["mode"] == "insecure"


def test_ca_bundle_is_accepted_and_recorded(tmp_path: Path) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(CERT), str(KEY))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_cli(
            "--target",
            f"https://127.0.0.1:{httpd.server_port}/",
            "--lab-mode",
            "--ca-bundle",
            str(CERT),
            "--depth",
            "0",
            "--output-dir",
            str(tmp_path),
            "--quiet",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        metadata = json.loads((tmp_path / "scan.json").read_text())
        assert metadata["tls"]["mode"] == "custom-ca"
    finally:
        httpd.shutdown()


def test_budget_flags_are_recorded(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    result = run_cli(
        "--target",
        f"http://127.0.0.1:{server.server_port}/",
        "--lab-mode",
        "--max-total-bytes",
        "100000",
        "--max-time",
        "20",
        "--max-links-per-page",
        "50",
        "--max-url-length",
        "1000",
        "--max-query-variants",
        "10",
        "--depth",
        "0",
        "--output-dir",
        str(tmp_path),
        "--quiet",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["budgets"] == {
        "max_total_bytes": 100000,
        "max_time": 20.0,
        "max_links_per_page": 50,
        "max_url_length": 1000,
        "max_query_variants": 10,
        "bytes_downloaded": metadata["budgets"]["bytes_downloaded"],
        "links_suppressed": metadata["budgets"]["links_suppressed"],
        "query_variants_suppressed": metadata["budgets"]["query_variants_suppressed"],
    }
