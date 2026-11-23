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
import json
import logging
import os
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from core.exceptions import PathscopeError
from core.models import DiscoveredUrl
from core.resolver import SafeResolver
from core.security import (
    canonical_netloc,
    check_url,
    host_in_scope,
    hostname_of,
    is_private_host,
)
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
        self.block_private = block_private
        self.scan_secrets_enabled = scan_secrets_enabled
        self.scan_endpoints_enabled = scan_endpoints_enabled
        self.scan_js = scan_js
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

        self._finding_keys: set[tuple[Any, ...]] = set()
        self._queued: set[str] = set()

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
        queue: asyncio.Queue[tuple[str, int] | None] = asyncio.Queue()
        self._enqueue(queue, target, depth=0, source_url=self.start_url, method="seed")

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
            if resolver is not None:
                await resolver.close()
            if self.persist:
                self.write_findings()

    def write_findings(self) -> str:
        """Write findings to ``<output_dir>/findings.json`` and return the path."""
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, "findings.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.findings, handle, indent=2, default=str)
        return path

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
        log.info("[%d] %s", depth, url)
        # Count the attempt before awaiting so failed requests are not invisible.
        self.requests_made += 1
        try:
            result = await fetch_response(
                session,
                url,
                timeout=self.timeout,
                max_redirects=self.max_redirects,
                max_bytes=self.max_bytes,
                allow_redirect_to=self._redirect_allowed,
            )
        except PathscopeError as exc:
            self._record_error(url, exc)
            return
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception as exc:  # defensive: a single URL must never kill the crawl
            self._record_error(url, exc)
            return

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
        self.discovered_urls.append(
            DiscoveredUrl.from_url(
                url,
                depth=depth,
                source_url=source_url,
                discovery_method=method,
                parent_url=source_url,
            )
        )
        queue.put_nowait((url, depth))

    # -- helpers ------------------------------------------------------------

    def _redirect_allowed(self, target: str) -> bool:
        if not host_in_scope(target, self.base_host):
            log.warning("refusing redirect outside scope: %s", target)
            return False
        if self.block_private and is_private_host(hostname_of(target)):
            log.warning("refusing redirect to private address: %s", target)
            return False
        return True

    def _scan(self, result: FetchResult, requested_url: str) -> None:
        page_url = result.url or requested_url
        is_js = _looks_like_javascript(page_url, result.content_type)
        if is_js and not self.scan_js:
            return

        if self.scan_endpoints_enabled:
            for finding in scan_endpoints(page_url, result.text):
                self._add_finding(finding, key=("endpoint", finding.get("endpoint")))

        if self.scan_secrets_enabled:
            for finding in scan_secrets(page_url, result.text):
                self._add_finding(
                    finding,
                    key=("secret", finding.get("pattern"), finding.get("line", 0)),
                )

    def _add_finding(self, finding: dict[str, Any], *, key: tuple[Any, ...]) -> None:
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(finding)
        if finding.get("type") == "endpoint":
            self.endpoints.append(finding)

    def _mark_crawled(self, url: str, result: FetchResult) -> None:
        for discovered in self.discovered_urls:
            if discovered.normalized == normalize(url):
                discovered.crawled = True
                discovered.url = result.url or discovered.url
                break

    def _record_error(self, url: str, exc: BaseException) -> None:
        self.errors.append(
            {
                "url": url,
                "type": type(exc).__name__,
                "reason": str(exc),
            }
        )
        log.warning("scan error on %s: %s", url, exc)

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


def _looks_like_javascript(url: str, content_type: str) -> bool:
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if "javascript" in media_type or "ecmascript" in media_type:
        return True
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs"))
