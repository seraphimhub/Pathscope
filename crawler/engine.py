"""Asynchronous crawl engine with bounded concurrency and error isolation.

Design constraints:

* A crawl uses a fixed pool of ``workers`` coroutines pulling from a queue, so
  outstanding requests are bounded regardless of how many links a page exposes.
* One failing URL never aborts the crawl: the failure is recorded in
  ``engine.errors`` and the remaining queue continues.
* Every URL is checked against the scope/address policy before it is queued and
  again for each redirect hop.
* Findings are deduplicated and carry the page URL they came from.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import tempfile
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from core.audit import AuditLog, config_hash
from core.exceptions import PathscopeError
from core.models import DiscoveredUrl
from core.redaction import redact_text, redact_url
from core.resolver import SafeResolver
from core.robots import RobotsPolicy
from core.security import (
    canonical_netloc,
    check_url,
    host_in_scope,
    hostname_of,
    is_private_host,
)
from core.throttle import RateLimiter
from core.version import DEFAULT_USER_AGENT
from crawler.fetcher import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT,
    FetchResult,
    fetch_response,
)
from crawler.parser import extract_links, normalize
from scanners.endpoints import scan_endpoints
from scanners.secrets import scan_secrets

log = logging.getLogger("pathscope.engine")

DEFAULT_WORKERS = 8
DEFAULT_MAX_PAGES = 1000
RETRY_STATUSES = frozenset({429, 503})
CIRCUIT_MIN_ATTEMPTS = 20
CIRCUIT_MAX_SLEEP = 30.0


class Engine:
    """Breadth-first crawler that collects endpoints and secret-pattern findings."""

    def __init__(
        self,
        start_url: str,
        depth: int = 20,
        *,
        workers: int = DEFAULT_WORKERS,
        timeout: float = DEFAULT_TIMEOUT,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        headers: dict[str, str] | None = None,
        block_private: bool = False,
        scan_secrets_enabled: bool = True,
        scan_endpoints_enabled: bool = True,
        scan_js: bool = True,
        allow_scheme_downgrade: bool = False,
        robots_policy: str = "off",
        rps: float = 0.0,
        delay: float = 0.0,
        jitter: float = 0.0,
        max_retries: int = 2,
        max_error_rate: float = 0.5,
        scan_id: str = "",
        user_agent: str = DEFAULT_USER_AGENT,
        authorization: dict[str, Any] | None = None,
        persist: bool = True,
        output_dir: str = "output",
    ) -> None:
        self.start_url = start_url
        try:
            self.base_host = canonical_netloc(start_url)
        except ValueError:
            # An invalid port cannot define a scope; every URL will fail closed.
            self.base_host = ""
        self.max_depth = max(0, depth)
        self.workers = max(1, workers)
        self.timeout = timeout
        self.max_pages = max(1, max_pages)
        self.max_redirects = max(0, max_redirects)
        self.max_bytes = max(1024, max_bytes)
        self.headers = dict(headers or {})
        self._ensure_identity_headers(scan_id=scan_id, user_agent=user_agent)
        self.block_private = block_private
        self.scan_secrets_enabled = scan_secrets_enabled
        self.scan_endpoints_enabled = scan_endpoints_enabled
        self.scan_js = scan_js
        self.allow_scheme_downgrade = allow_scheme_downgrade
        self.robots_policy = (
            robots_policy if robots_policy in {"off", "report", "respect"} else "off"
        )
        self.rps = max(0.0, rps)
        self.delay = max(0.0, delay)
        self.jitter = max(0.0, jitter)
        self.max_retries = max(0, max_retries)
        self.max_error_rate = min(1.0, max(0.0, max_error_rate))
        self.scan_id = scan_id
        self.user_agent = user_agent
        self.authorization = authorization
        self.persist = persist
        self.output_dir = output_dir

        self.visited: set[str] = set()
        self.findings: list[dict[str, Any]] = []
        self.discovered_urls: list[DiscoveredUrl] = []
        self.endpoints: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.elapsed: float = 0.0
        self.pages_fetched: int = 0
        self.requests_made: int = 0
        self.redirects_followed: int = 0
        self.status_counts: dict[int, int] = {}
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.attempts: int = 0
        self.failures: int = 0
        self.circuit_open: bool = False
        self.circuit_reason: str = ""
        self.robots_blocked: int = 0
        self.robots_reported: int = 0

        self._limiter = RateLimiter(rps=self.rps, delay=self.delay, jitter=self.jitter)
        self._robots = RobotsPolicy()
        self._audit: AuditLog | None = None
        self.audit_error: str = ""
        self._findings_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._queued: set[str] = set()
        self._discovered_by_url: dict[str, DiscoveredUrl] = {}

    # -- public API ---------------------------------------------------------

    @property
    def successful_pages(self) -> int:
        """Number of fetches that returned a 2xx status."""
        return sum(count for status, count in self.status_counts.items() if 200 <= status < 300)

    @property
    def failed_pages(self) -> int:
        """Number of fetches that returned a 4xx/5xx status."""
        return sum(count for status, count in self.status_counts.items() if status >= 400)

    async def run(self) -> None:
        """Crawl from ``start_url`` and persist findings when configured."""
        target = normalize(
            check_url(
                self.start_url,
                allowed_netloc=self.base_host,
                block_private=self.block_private,
            )
        )

        started = time.perf_counter()
        self.started_at = datetime.now(UTC)
        if self.persist:
            self._start_audit()
        queue: asyncio.Queue[tuple[str, int] | None] = asyncio.Queue()

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        resolver = SafeResolver(allow_private=False) if self.block_private else None
        connector = aiohttp.TCPConnector(
            limit=self.workers * 2,
            resolver=resolver,
            ttl_dns_cache=0,
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.headers,
            ) as session:
                if self.robots_policy != "off":
                    await self._load_robots(session)
                if self._robots_permits(target):
                    self._enqueue(queue, target, depth=0, source_url=self.start_url, method="seed")
                workers = [
                    asyncio.create_task(self._worker(session, queue), name=f"pathscope-{i}")
                    for i in range(self.workers)
                ]
                try:
                    await queue.join()
                finally:
                    for _ in workers:
                        queue.put_nowait(None)
                    await asyncio.gather(*workers, return_exceptions=True)
        finally:
            self.elapsed = time.perf_counter() - started
            self.finished_at = datetime.now(UTC)
            if resolver is not None:
                await resolver.close()
            if self._audit is not None:
                self._audit.record(
                    "scan_stop",
                    counters=self._counter_snapshot(),
                    circuit_open=self.circuit_open,
                    circuit_reason=self.circuit_reason,
                    audit_failed=bool(self.audit_error),
                )
                self._audit.close()
                self._audit = None
            if self.persist:
                self.write_findings()

    def write_findings(self) -> str:
        """Write findings and scan metadata, returning the findings path.

        ``findings.json`` keeps its historical list shape; scan metadata and
        the full error list go to ``scan.json`` in the same directory. Both
        files are written atomically and are readable by the owner only.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, "findings.json")
        _write_json_atomic(path, self.findings)
        _write_json_atomic(os.path.join(self.output_dir, "scan.json"), self.scan_metadata())
        return path

    def scan_metadata(self) -> dict[str, Any]:
        """Return a JSON-safe, credential-free description of this scan."""
        finished = self.finished_at or datetime.now(UTC)
        started = self.started_at or finished
        return {
            "tool": "pathscope",
            "target": redact_url(self.start_url),
            "scope": self.base_host,
            "scan_id": self.scan_id,
            "user_agent": self.user_agent,
            "authorization": self.authorization,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "elapsed": round(self.elapsed, 3),
            "elapsed_seconds": round((finished - started).total_seconds(), 3),
            "counters": self._counter_snapshot(),
            "config": self._effective_config(),
            "rate_limit": {
                "rps": self.rps,
                "delay": self.delay,
                "jitter": self.jitter,
                "max_retries": self.max_retries,
            },
            "robots": {
                "policy": self.robots_policy,
                "blocked": self.robots_blocked,
                "reported": self.robots_reported,
            },
            "circuit_breaker": {
                "open": self.circuit_open,
                "reason": self.circuit_reason,
                "attempts": self.attempts,
                "failures": self.failures,
                "max_error_rate": self.max_error_rate,
            },
            "audit_log": os.path.join(self.output_dir, "audit.jsonl") if self.persist else None,
            "audit_error": self.audit_error or None,
            "status_counts": {str(status): count for status, count in self.status_counts.items()},
            "errors": self.errors,
        }

    def _counter_snapshot(self) -> dict[str, int]:
        return {
            "discovered": len(self.discovered_urls),
            "pages": self.pages_fetched,
            "requests": self.requests_made,
            "successful": self.successful_pages,
            "failed": self.failed_pages,
            "redirects": self.redirects_followed,
            "findings": len(self.findings),
            "endpoints": len(self.endpoints),
            "errors": len(self.errors),
            "attempts": self.attempts,
            "failures": self.failures,
        }

    def _effective_config(self) -> dict[str, Any]:
        return {
            "depth": self.max_depth,
            "workers": self.workers,
            "max_pages": self.max_pages,
            "timeout": self.timeout,
            "max_redirects": self.max_redirects,
            "block_private": self.block_private,
            "allow_scheme_downgrade": self.allow_scheme_downgrade,
            "secrets": self.scan_secrets_enabled,
            "endpoints": self.scan_endpoints_enabled,
            "js": self.scan_js,
            "robots": self.robots_policy,
            "rps": self.rps,
            "delay": self.delay,
            "jitter": self.jitter,
            "max_retries": self.max_retries,
            "max_error_rate": self.max_error_rate,
        }

    def _start_audit(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        self._audit = AuditLog(os.path.join(self.output_dir, "audit.jsonl"))
        self.audit_error = "write failed" if self._audit.failed else ""
        self._audit.record(
            "scan_start",
            target=redact_url(self.start_url),
            scope=self.base_host,
            authorization=self.authorization,
            config_hash=config_hash(self._effective_config()),
            user_agent=self.user_agent,
            scan_id=self.scan_id,
        )

    def _ensure_identity_headers(self, *, scan_id: str, user_agent: str) -> None:
        lower = {name.lower() for name in self.headers}
        if "user-agent" not in lower and user_agent:
            self.headers["User-Agent"] = user_agent
        if scan_id and "x-pathscope-scan-id" not in lower:
            self.headers["X-Pathscope-Scan-Id"] = scan_id

    async def _load_robots(self, session: aiohttp.ClientSession) -> None:
        robots_url = urljoin(self.start_url, "/robots.txt")
        try:
            check_url(
                robots_url,
                allowed_netloc=self.base_host,
                block_private=self.block_private,
            )
            await self._limiter.wait()
            self.requests_made += 1
            self.attempts += 1
            result = await fetch_response(
                session,
                robots_url,
                timeout=self.timeout,
                max_redirects=0,
                max_bytes=self.max_bytes,
                allow_redirect_to=self._redirect_allowed,
                allow_scheme_downgrade=self.allow_scheme_downgrade,
            )
        except Exception as exc:
            self._record_error(robots_url, exc)
            self._audit_event("robots_unavailable", url=robots_url, reason=str(exc))
            return

        if result.status == 200 and result.text:
            self._robots = RobotsPolicy.parse(result.text, source=robots_url)
            self._audit_event(
                "robots_loaded",
                url=robots_url,
                rules=len(self._robots.rules),
                policy=self.robots_policy,
            )

    def _robots_permits(self, url: str) -> bool:
        if self.robots_policy == "off" or not self._robots.rules:
            return True
        path = urlparse(url).path or "/"
        if self._robots.allows(path):
            return True
        if self.robots_policy == "respect":
            self.robots_blocked += 1
            self._audit_event(
                "refused",
                url=url,
                stage="robots",
                reason="robots.txt disallows this path",
            )
            log.info("robots.txt disallows %s", redact_url(url))
            return False
        self.robots_reported += 1
        self._audit_event(
            "robots_report",
            url=url,
            stage="robots",
            reason="robots.txt disallows this path (report only)",
        )
        return True

    def _audit_event(self, event: str, **fields: Any) -> None:
        if self._audit is not None:
            self._audit.record(event, **fields)

    # -- crawl loop ---------------------------------------------------------

    async def _worker(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue[tuple[str, int] | None],
    ) -> None:
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                if self.circuit_open:
                    continue
                url, depth = item
                await self._visit(session, queue, url, depth)
            except asyncio.CancelledError:  # pragma: no cover - shutdown path
                raise
            except Exception as exc:  # a worker crash must be visible, never silent
                log.exception("worker failure")
                self._record_error(item[0] if item else "<worker>", exc)
            finally:
                queue.task_done()

    async def _visit(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue[tuple[str, int] | None],
        url: str,
        depth: int,
    ) -> None:
        log.info("[%d] %s", depth, redact_url(url))
        attempt = 0
        while True:
            if self.circuit_open:
                return
            await self._limiter.wait()
            # Count the attempt before awaiting so failed requests are not invisible.
            self.requests_made += 1
            self.attempts += 1
            try:
                result = await fetch_response(
                    session,
                    url,
                    timeout=self.timeout,
                    max_redirects=self.max_redirects,
                    max_bytes=self.max_bytes,
                    allow_redirect_to=self._redirect_allowed,
                    allow_scheme_downgrade=self.allow_scheme_downgrade,
                )
            except PathscopeError as exc:
                self.failures += 1
                self._record_error(url, exc)
                self._audit_fetch_failure(url, exc)
                self._maybe_trip_circuit()
                return
            except asyncio.CancelledError:  # pragma: no cover - shutdown path
                raise
            except Exception as exc:  # defensive: a single URL must never kill the crawl
                self.failures += 1
                self._record_error(url, exc)
                self._maybe_trip_circuit()
                return

            if result.status in RETRY_STATUSES and attempt < self.max_retries:
                self.failures += 1
                pause = result.retry_after
                if pause is None:
                    pause = float(2**attempt)
                pause = min(CIRCUIT_MAX_SLEEP, max(0.0, pause))
                self._audit_event(
                    "retry",
                    url=url,
                    status=result.status,
                    delay=round(pause, 3),
                    attempt=attempt + 1,
                )
                await asyncio.sleep(pause)
                attempt += 1
                continue
            break

        if result.status >= 500:
            self.failures += 1
        self._maybe_trip_circuit()
        self.pages_fetched += 1
        self.requests_made += len(result.redirects)
        self.redirects_followed += len(result.redirects)
        self.status_counts[result.status] = self.status_counts.get(result.status, 0) + 1
        self._mark_crawled(url, result)

        if not result.text:
            return

        try:
            self._scan(result, url)
        except Exception as exc:  # scanner failure is isolated too
            self._record_error(url, exc)

        if depth >= self.max_depth or not self._looks_like_html(result):
            return

        try:
            links = extract_links(result.text, result.url, self.base_host)
        except Exception as exc:
            self._record_error(result.url, exc)
            return

        for link in sorted(links):
            await self._maybe_enqueue(queue, link, depth=depth + 1, source_url=url, method="link")

    async def _maybe_enqueue(
        self,
        queue: asyncio.Queue[tuple[str, int] | None],
        url: str,
        *,
        depth: int,
        source_url: str,
        method: str,
    ) -> None:
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        try:
            check_url(
                url,
                allowed_netloc=self.base_host,
                block_private=self.block_private,
            )
        except PathscopeError as exc:
            self._record_error(url, exc)
            self._audit_event("refused", url=url, stage="scope", reason=str(exc))
            return

        if not self._robots_permits(url):
            return
        normalized = normalize(url)
        if normalized in self.visited or normalized in self._queued:
            return
        self._enqueue(queue, normalized, depth=depth, source_url=source_url, method=method)

    def _enqueue(
        self,
        queue: asyncio.Queue[tuple[str, int] | None],
        url: str,
        *,
        depth: int,
        source_url: str,
        method: str,
    ) -> None:
        self._queued.add(url)
        self.visited.add(url)
        discovered = DiscoveredUrl.from_url(
            url,
            depth=depth,
            source_url=source_url,
            discovery_method=method,
            parent_url=source_url,
        )
        self.discovered_urls.append(discovered)
        self._discovered_by_url[normalize(url)] = discovered
        queue.put_nowait((url, depth))

    # -- helpers ------------------------------------------------------------

    def _redirect_allowed(self, target: str) -> bool:
        if not host_in_scope(target, self.base_host):
            log.warning("refusing redirect outside scope: %s", redact_url(target))
            self._audit_event(
                "refused",
                url=target,
                stage="redirect_scope",
                reason="redirect target outside the authorized host scope",
            )
            return False
        if self.block_private and is_private_host(hostname_of(target)):
            log.warning("refusing redirect to private address: %s", redact_url(target))
            self._audit_event(
                "refused",
                url=target,
                stage="redirect_private",
                reason="redirect target resolves to a private address",
            )
            return False
        return True

    def _audit_fetch_failure(self, url: str, exc: BaseException) -> None:
        reason = str(exc)
        # Redirect scope/private refusals are audited by _redirect_allowed; here
        # we only record the scheme policy, which the fetcher enforces itself.
        refusal_markers = ("cleartext", "unsupported redirect scheme")
        if any(marker in reason for marker in refusal_markers):
            self._audit_event("refused", url=url, stage="redirect", reason=reason)

    def _maybe_trip_circuit(self) -> None:
        if self.circuit_open or self.attempts < CIRCUIT_MIN_ATTEMPTS:
            return
        error_rate = self.failures / self.attempts
        if error_rate <= self.max_error_rate:
            return
        self.circuit_open = True
        self.circuit_reason = (
            f"error rate {error_rate:.2f} exceeded {self.max_error_rate:.2f} "
            f"after {self.attempts} attempts"
        )
        log.warning("circuit breaker open: %s", self.circuit_reason)
        self._audit_event(
            "circuit_open",
            reason=self.circuit_reason,
            attempts=self.attempts,
            failures=self.failures,
        )

    def _scan(self, result: FetchResult, requested_url: str) -> None:
        page_url = result.url or requested_url
        is_js = _looks_like_javascript(page_url, result.content_type)
        if is_js and not self.scan_js:
            return

        if self.scan_endpoints_enabled:
            for finding in scan_endpoints(page_url, result.text):
                self._add_finding(
                    finding,
                    key=("endpoint", finding.get("endpoint")),
                    page_url=page_url,
                )

        if self.scan_secrets_enabled:
            for finding in scan_secrets(page_url, result.text):
                self._add_finding(
                    finding,
                    key=(
                        "secret",
                        finding.get("url"),
                        finding.get("pattern"),
                        finding.get("line", 0),
                    ),
                    page_url=page_url,
                )

    def _add_finding(
        self,
        finding: dict[str, Any],
        *,
        key: tuple[Any, ...],
        page_url: str,
    ) -> None:
        page_url = redact_url(page_url)
        existing = self._findings_by_key.get(key)
        if existing is not None:
            # Endpoints are deduplicated globally, but every page that exposed
            # one is kept so a reviewer knows where to look.
            pages = existing.setdefault("pages", [])
            if page_url not in pages:
                pages.append(page_url)
            return
        finding = self._redact_finding(finding)
        if finding.get("type") == "endpoint":
            finding["pages"] = [page_url]
        self._findings_by_key[key] = finding
        self.findings.append(finding)
        if finding.get("type") == "endpoint":
            self.endpoints.append(finding)

    def _mark_crawled(self, url: str, result: FetchResult) -> None:
        discovered = self._discovered_by_url.get(normalize(url))
        if discovered is None:
            return
        discovered.crawled = True
        discovered.url = result.url or discovered.url

    @staticmethod
    def _redact_finding(finding: dict[str, Any]) -> dict[str, Any]:
        safe = dict(finding)
        for key in ("url", "endpoint"):
            if isinstance(safe.get(key), str):
                safe[key] = redact_url(safe[key])
        if isinstance(safe.get("evidence"), str):
            safe["evidence"] = redact_text(safe["evidence"])
        return safe

    def _record_error(self, url: str, exc: BaseException) -> None:
        safe_url = redact_url(url)
        reason = redact_text(str(exc))
        self.errors.append(
            {
                "url": safe_url,
                "type": type(exc).__name__,
                "reason": reason,
            }
        )
        log.warning("scan error on %s: %s", safe_url, reason)

    @staticmethod
    def _looks_like_html(result: FetchResult) -> bool:
        media_type = (result.content_type or "").split(";", 1)[0].strip().lower()
        if media_type in {"text/html", "application/xhtml+xml"}:
            return True
        if media_type in {"application/xml", "text/xml"}:
            return False
        if not media_type:
            return not _looks_like_javascript(result.url, result.content_type)
        return False


def _write_json_atomic(path: str, payload: Any) -> None:
    """Write ``payload`` to ``path`` atomically with owner-only permissions."""
    directory = os.path.dirname(path) or "."
    descriptor, temporary = tempfile.mkstemp(prefix=".pathscope-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _looks_like_javascript(url: str, content_type: str) -> bool:
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if "javascript" in media_type or "ecmascript" in media_type:
        return True
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs"))
