"""Phase 1 controls at the engine boundary: pacing, retries, circuit, robots,
audit, identity headers, and redaction of everything that is persisted.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from core.exceptions import FetchError
from core.version import DEFAULT_USER_AGENT
from crawler.engine import Engine


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class OpsHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []
    headers_seen: ClassVar[dict[str, str]] = {}
    robots_text: ClassVar[str] = "User-agent: *\nDisallow: /private\n"
    retry_remaining: ClassVar[int] = 0
    lock: ClassVar[threading.Lock] = threading.Lock()

    def do_GET(self) -> None:
        with OpsHandler.lock:
            OpsHandler.hits.append(self.path)
            OpsHandler.headers_seen = {key: value for key, value in self.headers.items()}
        path = self.path

        if path == "/robots.txt":
            self._body(OpsHandler.robots_text, "text/plain")
        elif path == "/":
            self._html('<a href="/public">p</a><a href="/private/x">s</a>')
        elif path == "/public":
            self._html("<html><body>public</body></html>")
        elif path.startswith("/private"):
            self._html("<html><body>private</body></html>")
        elif path == "/retry":
            with OpsHandler.lock:
                remaining = OpsHandler.retry_remaining
                if remaining > 0:
                    OpsHandler.retry_remaining -= 1
            if remaining > 0:
                self.send_response(503)
                self.send_header("Retry-After", "0")
                self.end_headers()
            else:
                self._html("<html><body>recovered</body></html>")
        elif path == "/fail-root":
            links = "".join(f'<a href="/fail{i}">f</a>' for i in range(30))
            self._html(f"<html><body>{links}</body></html>")
        elif path.startswith("/fail"):
            self.send_response(500)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
        elif path == "/paced":
            links = "".join(f'<a href="/pace{i}">p</a>' for i in range(4))
            self._html(f"<html><body>{links}</body></html>")
        else:
            self._html("<html><body>leaf</body></html>")

    def _html(self, body: str) -> None:
        self._body(body, "text/html")

    def _body(self, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture()
def server() -> ThreadingHTTPServer:
    OpsHandler.hits = []
    OpsHandler.headers_seen = {}
    OpsHandler.robots_text = "User-agent: *\nDisallow: /private\n"
    OpsHandler.retry_remaining = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", find_free_port()), OpsHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ---------------------------------------------------------------------------
# robots.txt policy
# ---------------------------------------------------------------------------


def test_robots_respect_skips_disallowed_urls(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(server) + "/",
        depth=1,
        workers=2,
        robots_policy="respect",
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    assert "/private/x" not in OpsHandler.hits
    assert "/public" in OpsHandler.hits
    assert engine.robots_blocked == 1
    events = read_jsonl(tmp_path / "audit.jsonl")
    assert any(event["event"] == "refused" and event.get("stage") == "robots" for event in events)
    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert metadata["robots"] == {"policy": "respect", "blocked": 1, "reported": 0}


def test_robots_report_crawls_but_records_the_decision(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(
        base_url(server) + "/",
        depth=1,
        workers=2,
        robots_policy="report",
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    assert "/private/x" in OpsHandler.hits
    assert engine.robots_reported == 1
    assert engine.robots_blocked == 0
    events = read_jsonl(tmp_path / "audit.jsonl")
    assert any(event["event"] == "robots_report" for event in events)


def test_robots_off_never_requests_the_file(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/", depth=1, workers=2, persist=False)
    asyncio.run(engine.run())

    assert "/robots.txt" not in OpsHandler.hits
    assert "/private/x" in OpsHandler.hits


# ---------------------------------------------------------------------------
# Retry-After and circuit breaker
# ---------------------------------------------------------------------------


def test_retry_after_is_honored_for_503(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    OpsHandler.retry_remaining = 2
    engine = Engine(
        base_url(server) + "/retry",
        depth=0,
        workers=1,
        max_retries=2,
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert metadata["status_counts"] == {"200": 1}
    assert metadata["counters"]["requests"] == 3
    assert metadata["counters"]["failures"] == 2
    retries = [event for event in read_jsonl(tmp_path / "audit.jsonl") if event["event"] == "retry"]
    assert len(retries) == 2
    assert all(event["delay"] == 0 for event in retries)


def test_circuit_breaker_stops_a_failing_scan(server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(server) + "/fail-root",
        depth=1,
        workers=4,
        max_retries=0,
        max_error_rate=0.4,
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    assert engine.circuit_open is True
    assert engine.attempts >= 20
    # The 30 discovered leaves are not all fetched after the breaker opens.
    assert metadata_requests(tmp_path) < len(engine.discovered_urls)
    events = read_jsonl(tmp_path / "audit.jsonl")
    assert any(event["event"] == "circuit_open" for event in events)
    stop = next(event for event in events if event["event"] == "scan_stop")
    assert stop["circuit_open"] is True


def test_healthy_scan_does_not_open_the_circuit(server: ThreadingHTTPServer) -> None:
    engine = Engine(base_url(server) + "/public", depth=0, workers=1, persist=False)
    asyncio.run(engine.run())
    assert engine.circuit_open is False
    assert engine.failures == 0


def metadata_requests(tmp_path: Path) -> int:
    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    return int(metadata["counters"]["requests"])


# ---------------------------------------------------------------------------
# Pacing
# ---------------------------------------------------------------------------


def test_rate_limit_paces_request_starts(server: ThreadingHTTPServer) -> None:
    engine = Engine(
        base_url(server) + "/paced",
        depth=1,
        workers=4,
        rps=20.0,
        persist=False,
    )
    started = time.monotonic()
    asyncio.run(engine.run())
    elapsed = time.monotonic() - started

    assert engine.attempts == 5
    # Five slots at 20 rps means four gaps of ~50 ms.
    assert elapsed >= 0.15


# ---------------------------------------------------------------------------
# Identity headers
# ---------------------------------------------------------------------------


def test_user_agent_and_scan_id_are_sent(server: ThreadingHTTPServer) -> None:
    engine = Engine(
        base_url(server) + "/public",
        depth=0,
        workers=1,
        scan_id="scan-abc",
        user_agent="Pathscope-test/9.9",
        persist=False,
    )
    asyncio.run(engine.run())

    assert OpsHandler.headers_seen["User-Agent"] == "Pathscope-test/9.9"
    assert OpsHandler.headers_seen["X-Pathscope-Scan-Id"] == "scan-abc"


def test_default_user_agent_is_honest_and_not_aiohttp() -> None:
    engine = Engine("http://127.0.0.1:1/", persist=False)
    assert engine.headers["User-Agent"] == DEFAULT_USER_AGENT
    assert "aiohttp" not in engine.headers["User-Agent"]
    assert "Pathscope/" in engine.headers["User-Agent"]


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_audit_log_is_append_only_private_and_complete(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    for _ in range(2):
        engine = Engine(
            base_url(server) + "/",
            depth=1,
            workers=2,
            persist=True,
            output_dir=str(tmp_path),
        )
        asyncio.run(engine.run())

    path = tmp_path / "audit.jsonl"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    events = read_jsonl(path)
    starts = [event for event in events if event["event"] == "scan_start"]
    stops = [event for event in events if event["event"] == "scan_stop"]
    assert len(starts) == 2 and len(stops) == 2
    for event in starts:
        assert len(str(event["config_hash"])) == 64
        # Engine used directly has no CLI authorization block; the CLI always
        # supplies one, and that path is covered by the CLI tests.
        assert event["authorization"] is None
        assert event["target"].startswith("http://127.0.0.1:")


def test_audit_and_metadata_never_store_start_url_credentials(
    server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(
        f"http://user:supersecret@127.0.0.1:{server.server_port}/public",
        depth=0,
        workers=1,
        authorization={"mode": "lab", "owner": "me", "reference": "local"},
        persist=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    for name in ("scan.json", "findings.json", "audit.jsonl"):
        content = (tmp_path / name).read_text(encoding="utf-8")
        assert "supersecret" not in content, name
        assert "user:" not in content, name
    metadata = json.loads((tmp_path / "scan.json").read_text(encoding="utf-8"))
    assert metadata["target"] == f"http://127.0.0.1:{server.server_port}/public"
    assert metadata["authorization"]["mode"] == "lab"


def test_crafted_exception_credentials_are_redacted_in_errors() -> None:
    engine = Engine("http://127.0.0.1:1/", persist=False)
    error = FetchError(
        "https://user:topsecret@example.com/x",
        reason="Authorization: Bearer abc123; Cookie: session=deadbeef",
    )
    engine._record_error("https://user:topsecret@example.com/x", error)

    stored = json.dumps(engine.errors)
    for leaked in ("topsecret", "abc123", "deadbeef", "user:"):
        assert leaked not in stored
    assert "example.com" in stored


def test_findings_redact_url_credentials_and_evidence() -> None:
    engine = Engine("http://127.0.0.1:1/", persist=False)
    engine._add_finding(
        {
            "type": "secret_pattern",
            "url": "https://user:pass@example.com/app.js",
            "pattern": "token",
            "category": "token",
            "line": 1,
            "evidence": 'var token = "abc"; Authorization: Bearer zzz',
        },
        key=("secret", "x", 1),
        page_url="https://user:pass@example.com/app.js",
    )

    finding = engine.findings[0]
    assert finding["url"] == "https://example.com/app.js"
    assert "pass" not in json.dumps(finding)
    assert "abc" not in finding["evidence"]
    assert "zzz" not in finding["evidence"]
