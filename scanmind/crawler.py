"""Same-origin crawler: fetch HTML pages plus their same-origin JS/CSS assets."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from .fetch import fetch


@dataclass
class Page:
    url: str
    status: int | None
    headers: dict[str, str]
    content_type: str
    body: str
    ok: bool

    @property
    def is_html(self) -> bool:
        ct = self.content_type.lower()
        return "html" in ct or "html" in self.headers.get("content-type", "")

    @property
    def is_javascript(self) -> bool:
        ct = self.content_type.lower()
        return "javascript" in ct or self.url.split("?")[0].endswith(".js")

    @property
    def is_https(self) -> bool:
        return urlparse(self.url).scheme == "https"


def _normalize(base_url: str, href: str) -> str:
    return urldefrag(urljoin(base_url, href))[0]


def _same_site(first: str, second: str) -> bool:
    a, b = urlparse(first), urlparse(second)
    try:
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except ValueError:
        return False


def extract_links(base_url: str, html: str) -> tuple[list[str], list[str]]:
    """Return (page_links, asset_links) that stay on the scanned origin."""
    soup = BeautifulSoup(html, "html.parser")
    pages: list[str] = []
    assets: list[str] = []

    for tag in soup.find_all("a", href=True):
        url = _normalize(base_url, tag["href"])
        if url.startswith(("http://", "https://")) and _same_site(url, base_url):
            pages.append(url)

    for tag in soup.find_all("script", src=True):
        url = _normalize(base_url, tag["src"])
        if url.startswith(("http://", "https://")) and _same_site(url, base_url):
            assets.append(url)

    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel") or []).lower()
        if "stylesheet" not in rel:
            continue
        url = _normalize(base_url, tag["href"])
        if url.startswith(("http://", "https://")) and _same_site(url, base_url):
            assets.append(url)

    # de-duplicate while preserving order
    seen_pages: set[str] = set()
    seen_assets: set[str] = set()
    pages = [u for u in pages if not (u in seen_pages or seen_pages.add(u))]
    assets = [u for u in assets if not (u in seen_assets or seen_assets.add(u))]
    return pages, assets


def crawl(
    start_url: str,
    session,
    *,
    max_pages: int = 8,
    max_assets: int = 10,
    max_depth: int = 2,
    timeout: float = 10.0,
    delay: float = 0.1,
) -> tuple[list[Page], list[Page]]:
    """Breadth-first crawl of the start URL. Returns (html_pages, asset_pages)."""
    pages: list[Page] = []
    assets: list[Page] = []
    visited: set[str] = set()
    queue: deque[tuple[str, int, bool]] = deque([(start_url, 0, False)])

    budget = max_pages + max_assets
    while queue and len(pages) < max_pages and (len(pages) + len(assets)) < budget:
        url, depth, is_asset = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        result = fetch(session, url, timeout=timeout)
        if delay:
            time.sleep(delay)

        page = Page(
            url=result.url or url,
            status=result.status,
            headers=result.headers,
            content_type=result.content_type,
            body=result.text,
            ok=result.ok,
        )

        if is_asset:
            if page.ok:
                assets.append(page)
            continue
        if not page.ok:
            continue

        pages.append(page)
        if depth >= max_depth:
            continue
        page_links, asset_links = extract_links(page.url, page.body)
        for link in page_links:
            if link not in visited:
                queue.append((link, depth + 1, False))
        for link in asset_links:
            if link not in visited:
                queue.append((link, depth + 1, True))

    return pages, assets
