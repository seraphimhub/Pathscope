"""HTTP fetching with bounded redirects, size limits, and content sniffing.

The crawler must never be able to: follow an unbounded redirect chain, follow a
redirect out of its authorized host, or buffer an arbitrarily large body. All
three limits are enforced here rather than in the engine so that every caller
inherits them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

import aiohttp

from core.exceptions import FetchError
from core.security import redirect_scheme_violation

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/x-www-form-urlencoded",
    "application/ld+json",
)

DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 2_000_000


@dataclass(slots=True)
class FetchResult:
    """Outcome of a single logical fetch, including the redirect chain."""

    url: str
    status: int = 0
    text: str = ""
    content_type: str = ""
    redirects: tuple[str, ...] = field(default_factory=tuple)
    truncated: bool = False
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        """True when the request completed with a success status."""
        return 200 <= self.status < 400

    @property
    def is_text(self) -> bool:
        """True when the body is text and safe to scan."""
        return bool(self.text)


def is_text_content_type(content_type: str) -> bool:
    """Return True when ``content_type`` denotes a scannable text payload."""
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if not media_type:
        # Servers without a Content-Type are treated as text; the size cap and
        # decode error handling keep that safe.
        return True
    return any(
        media_type.startswith(prefix) or media_type == prefix for prefix in TEXT_CONTENT_TYPES
    )


async def fetch_response(
    session: aiohttp.ClientSession | None,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_redirect_to: Callable[[str], bool] | None = None,
    allow_scheme_downgrade: bool = False,
) -> FetchResult:
    """Fetch ``url`` following at most ``max_redirects`` hops.

    ``allow_redirect_to`` is consulted for every hop and may veto it (raise or
    return False); the engine uses it to keep redirects inside the scan scope.
    Every hop is also checked for an https -> http downgrade, which would send
    session headers in cleartext; set ``allow_scheme_downgrade`` to opt in.
    """
    if session is None:
        return FetchResult(url=url)

    current = url
    chain: list[str] = []
    redirect_budget = max(0, max_redirects)

    for _ in range(redirect_budget + 1):
        try:
            async with session.get(
                current,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                location = resp.headers.get("Location")
                if resp.status in REDIRECT_STATUSES and location:
                    target = urljoin(current, location)
                    if target in chain or target == current:
                        raise FetchError(current, reason="redirect loop detected")
                    scheme_violation = redirect_scheme_violation(
                        current,
                        target,
                        allow_scheme_downgrade=allow_scheme_downgrade,
                    )
                    if scheme_violation is not None:
                        raise FetchError(target, reason=scheme_violation)
                    if allow_redirect_to is not None and not allow_redirect_to(target):
                        raise FetchError(target, reason="redirect target rejected by scope policy")
                    if len(chain) >= redirect_budget:
                        raise FetchError(
                            current, reason=f"redirect limit exceeded ({redirect_budget})"
                        )
                    chain.append(target)
                    current = target
                    continue

                content_type = resp.headers.get("Content-Type", "")
                retry_after = _retry_after_seconds(resp.headers.get("Retry-After"))
                if not is_text_content_type(content_type):
                    return FetchResult(
                        url=current,
                        status=resp.status,
                        content_type=content_type,
                        redirects=tuple(chain),
                        retry_after=retry_after,
                    )

                text, truncated = await _read_text(resp, max_bytes)
                return FetchResult(
                    url=current,
                    status=resp.status,
                    text=_for_status(resp.status, text),
                    content_type=content_type,
                    redirects=tuple(chain),
                    truncated=truncated,
                    retry_after=retry_after,
                )
        except aiohttp.ClientResponseError:
            # Surfaced only when raise_for_status is enabled; treat as empty.
            return FetchResult(url=current, redirects=tuple(chain))
        except FetchError:
            raise
        except aiohttp.ClientError as exc:
            raise FetchError(current, reason=str(exc)) from exc
        except Exception as exc:  # pragma: no cover - defensive boundary
            raise FetchError(current, reason=str(exc)) from exc

    raise FetchError(url, reason=f"redirect limit exceeded ({redirect_budget})")


async def fetch(
    session: aiohttp.ClientSession | None,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_redirect_to: Callable[[str], bool] | None = None,
    allow_scheme_downgrade: bool = False,
) -> str:
    """Fetch a URL and return its text body (empty string for non-text/error)."""
    result = await fetch_response(
        session,
        url,
        timeout=timeout,
        max_redirects=max_redirects,
        max_bytes=max_bytes,
        allow_redirect_to=allow_redirect_to,
        allow_scheme_downgrade=allow_scheme_downgrade,
    )
    return result.text


def _retry_after_seconds(value: str | None) -> float | None:
    """Parse ``Retry-After`` as delta seconds or an HTTP date."""
    if not value:
        return None
    candidate = value.strip()
    try:
        seconds = float(candidate)
    except ValueError:
        try:
            when = parsedate_to_datetime(candidate)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    return max(0.0, seconds)


def _for_status(status: int, text: str) -> str:
    """Drop bodies of error responses; they carry no crawlable content."""
    if 200 <= status < 300:
        return text
    return ""


async def _read_text(resp: aiohttp.ClientResponse, max_bytes: int) -> tuple[str, bool]:
    """Read at most ``max_bytes`` and decode leniently.

    Returns ``(text, truncated)``.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        while True:
            chunk = await resp.content.read(65536)
            if not chunk:
                break
            remaining = max_bytes - total
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
    except Exception:
        return "", False

    raw = b"".join(chunks)
    if not raw:
        return "", truncated

    encoding = resp.charset or "utf-8"
    try:
        return raw.decode(encoding, errors="ignore"), truncated
    except LookupError:
        return raw.decode("utf-8", errors="ignore"), truncated
