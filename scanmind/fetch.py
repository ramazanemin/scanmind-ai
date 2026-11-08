"""Minimal HTTP fetch layer. Never raises - errors become FetchResult."""
from __future__ import annotations

from dataclasses import dataclass, field

try:
    import requests
except ImportError as exc:  # pragma: no cover - dependency missing
    raise RuntimeError(
        "ScanMind AI needs the 'requests' package. "
        "Install dependencies with: pip install -r requirements.txt"
    ) from exc

from . import __version__

DEFAULT_USER_AGENT = f"ScanMindAI/{__version__} (+security scanner; authorized use only)"


@dataclass
class FetchResult:
    url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    content_type: str = ""
    ok: bool = False
    error: str = ""

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def text_as(self, encoding: str) -> str:
        """Lossless-ish decode used for binary probes (magic byte checks)."""
        return self.content.decode(encoding, "replace")

    @property
    def is_html(self) -> bool:
        if "html" in self.content_type.lower():
            return True
        head = self.content[:512].lstrip().lower()
        return head.startswith((b"<!doctype html", b"<html"))


def create_session(user_agent: str = "", verify_tls: bool = True) -> "requests.Session":
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update(
        {
            "User-Agent": user_agent or DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    return session


def fetch(
    session: "requests.Session",
    url: str,
    timeout: float = 10.0,
    method: str = "GET",
) -> FetchResult:
    try:
        response = session.request(method, url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return FetchResult(url=url, error=f"{type(exc).__name__}: {exc}")
    return FetchResult(
        url=str(response.url),
        status=response.status_code,
        headers={str(k).lower(): str(v) for k, v in response.headers.items()},
        content=response.content,
        content_type=str(response.headers.get("Content-Type", "")),
        ok=response.status_code < 400,
    )
