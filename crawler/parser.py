"""HTML parsing: URL normalization and in-scope link/asset extraction."""

from __future__ import annotations

from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from core.security import host_in_scope

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


def extract_links(
    html: str,
    base_url: str,
    base_host: str,
    *,
    max_links: int = 0,
    max_url_length: int = 0,
    max_query_variants: int = 0,
    stats: dict[str, int] | None = None,
) -> set[str]:
    """Return normalized, in-scope http(s) URLs referenced by ``html``.

    ``max_links`` bounds the returned set, ``max_url_length`` drops oversized
    references, and ``max_query_variants`` bounds distinct queries per path
    (the crawler-trap defense). Suppressed counts are added to ``stats`` when a
    mapping is supplied; query strings are still discarded by ``normalize`` for
    backward-compatible page identity.
    """
    if stats is None:
        stats = {}
    stats.setdefault("links_suppressed", 0)
    stats.setdefault("query_variants_suppressed", 0)
    if not html or not base_url or not base_host:
        return set()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return set()

    links: set[str] = set()
    query_variants: dict[str, set[str]] = {}

    def admit(resolved: str) -> None:
        if max_url_length and len(resolved) > max_url_length:
            stats["links_suppressed"] += 1
            return
        parsed = urlparse(resolved)
        path = parsed.path or "/"
        if parsed.query:
            variants = query_variants.setdefault(path, set())
            if parsed.query not in variants:
                if max_query_variants and len(variants) >= max_query_variants:
                    stats["query_variants_suppressed"] += 1
                    return
                variants.add(parsed.query)
        normalized = normalize(resolved)
        if normalized in links:
            return
        if max_links and len(links) >= max_links:
            stats["links_suppressed"] += 1
            return
        links.add(normalized)

    for tag_name, attribute in _REFERENCE_ATTRS:
        for tag in soup.find_all(tag_name):
            raw = tag.get(attribute)
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            if not raw or not isinstance(raw, str):
                continue
            resolved = _resolve(raw, base_url, base_host)
            if resolved:
                admit(resolved)

            if tag_name in {"img", "source"}:
                for candidate in _srcset_urls(tag.get("srcset")):
                    resolved = _resolve(candidate, base_url, base_host)
                    if resolved:
                        admit(resolved)

    return links


def _resolve(raw: str, base_url: str, base_host: str) -> str | None:
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
    # One shared policy: IDNA, trailing dots, default ports and userinfo are all
    # normalized by core.security instead of being compared as raw strings here.
    if not host_in_scope(absolute, base_host):
        return None
    return absolute


def _srcset_urls(srcset: object) -> list[str]:
    if not isinstance(srcset, str):
        return []
    urls: list[str] = []
    for candidate in srcset.split(","):
        pieces = candidate.strip().split()
        if pieces:
            urls.append(pieces[0])
    return urls
