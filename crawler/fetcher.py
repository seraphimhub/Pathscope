from __future__ import annotations

import aiohttp


class FetchError(Exception):
    """Raised when a fetch does not return usable content."""

    def __init__(self, url: str, *, reason: str | None = None) -> None:
        self.url = url
        self.reason = reason or "fetch failed"
        super().__init__(self.reason)


async def fetch(
    session: aiohttp.ClientSession | None,
    url: str,
    *,
    timeout: float = 20.0,
) -> str:
    """Fetch a URL and return its text body.

    Returns an empty string on network errors or non-text responses.
    """
    if session is None:
        return ""

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            text = await _safe_text(resp)
            return text if text else ""
    except aiohttp.ClientResponseError:
        # Non-2xx responses can surface here depending on aiohttp configuration.
        return ""
    except aiohttp.ClientError as exc:
        raise FetchError(url, reason=str(exc)) from exc
    except Exception as exc:
        raise FetchError(url, reason=str(exc)) from exc


async def _safe_text(resp: aiohttp.ClientResponse) -> str:
    """Read the response body as text, ignoring decode errors."""
    try:
        return await resp.text(errors="ignore")
    except Exception:
        return ""
