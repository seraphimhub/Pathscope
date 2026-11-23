"""TLS verification defaults and explicit, recorded opt-outs.

The certificate and key under tests/fixtures/tls are a committed test fixture
for 127.0.0.1/localhost only; they are not trusted by any system store.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from core.exceptions import ScopeViolationError
from crawler.engine import Engine

CERT = Path(__file__).resolve().parents[1] / "fixtures" / "tls" / "cert.pem"
KEY = Path(__file__).resolve().parents[1] / "fixtures" / "tls" / "key.pem"


class TlsHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        TlsHandler.hits.append(self.path)
        payload = b"<html><body>secure</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture()
def tls_server() -> ThreadingHTTPServer:
    TlsHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), TlsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(CERT), str(KEY))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def base_url(server: ThreadingHTTPServer) -> str:
    return f"https://127.0.0.1:{server.server_port}"


def test_default_verification_fails_with_a_clear_error(
    tls_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(base_url(tls_server), depth=0, timeout=5, output_dir=str(tmp_path))
    asyncio.run(engine.run())

    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["tls"]["mode"] == "verify"
    assert metadata["counters"]["pages"] == 0
    assert metadata["errors"]
    reason = metadata["errors"][0]["reason"].lower()
    assert "certificate" in reason or "ssl" in reason


def test_ca_bundle_allows_the_self_signed_server(
    tls_server: ThreadingHTTPServer, tmp_path: Path
) -> None:
    engine = Engine(
        base_url(tls_server),
        depth=0,
        timeout=5,
        ca_bundle=str(CERT),
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["tls"]["mode"] == "custom-ca"
    assert metadata["tls"]["ca_bundle"] == str(CERT)
    assert metadata["counters"]["pages"] == 1
    assert metadata["errors"] == []


def test_insecure_is_recorded_and_audited(tls_server: ThreadingHTTPServer, tmp_path: Path) -> None:
    engine = Engine(
        base_url(tls_server),
        depth=0,
        timeout=5,
        insecure=True,
        output_dir=str(tmp_path),
    )
    asyncio.run(engine.run())

    metadata = json.loads((tmp_path / "scan.json").read_text())
    assert metadata["tls"] == {
        "mode": "insecure",
        "verify": False,
        "ca_bundle": None,
        "warning": "TLS certificate verification disabled by --insecure",
    }
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    start = next(event for event in events if event["event"] == "scan_start")
    assert start["tls"]["mode"] == "insecure"


@pytest.mark.parametrize("mode", ["verify", "insecure"])
def test_scope_and_private_checks_still_apply_in_every_tls_mode(
    tls_server: ThreadingHTTPServer, tmp_path: Path, mode: str
) -> None:
    engine = Engine(
        base_url(tls_server),
        depth=0,
        timeout=5,
        insecure=mode == "insecure",
        block_private=True,
        output_dir=str(tmp_path / mode),
    )
    with pytest.raises(ScopeViolationError) as excinfo:
        asyncio.run(engine.run())
    assert "private address blocked" in str(excinfo.value)
    assert TlsHandler.hits == []
