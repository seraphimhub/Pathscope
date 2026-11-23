"""HTML parsing: URL normalization and in-scope link/asset extraction."""

from __future__ import annotations

from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

# (tag, attribute) pairs whose values are crawlable references.
_REFERENCE_ATTRS: tuple[tuple[str, str], ...] = (
    ("a", "href"),
    ("area", "href"),
    ("link", "href"),
    ("script", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("img", "src"),
    ("source", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("embed", "src"),
    ("track", "src"),
    ("form", "action"),
)

_CRAWLABLE_SCHEMES = frozenset({"http", "https"})


def normalize(url: str) -> str:
    """Strip the fragment and the query, and rebuild ``scheme://netloc/path``.

    Query strings are dropped on purpose: Pathscope deduplicates pages by path,
    and endpoint discovery reports query-bearing API paths separately.
    """
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def extract_links(html: str, base_url: str, base_host: str) -> set[str]:
    """Return normalized, in-scope http(s) URLs referenced by ``html``."""
    if not html or not base_url or not base_host:
        return set()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return set()

    links: set[str] = set()
    target_host = (base_host or "").lower()

    for tag_name, attribute in _REFERENCE_ATTRS:
        for tag in soup.find_all(tag_name):
            raw = tag.get(attribute)
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            if not raw or not isinstance(raw, str):
                continue
            resolved = _resolve(raw, base_url, target_host)
            if resolved:
                links.add(resolved)

            if tag_name in {"img", "source"}:
                for candidate in _srcset_urls(tag.get("srcset")):
                    resolved = _resolve(candidate, base_url, target_host)
                    if resolved:
                        links.add(resolved)

    return links


def _resolve(raw: str, base_url: str, target_host: str) -> str | None:
    """Resolve one reference and keep it only when it stays in scope."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
    except ValueError:
        return None

    if parsed.scheme.lower() not in _CRAWLABLE_SCHEMES:
        return None
    if (parsed.netloc or "").lower() != target_host:
        return None
    return normalize(absolute)


def _srcset_urls(srcset: object) -> list[str]:
    if not isinstance(srcset, str):
        return []
    urls: list[str] = []
    for candidate in srcset.split(","):
        pieces = candidate.strip().split()
        if pieces:
            urls.append(pieces[0])
    return urls
