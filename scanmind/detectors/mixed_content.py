"""Mixed content: http:// subresources on https:// pages."""
from __future__ import annotations

from bs4 import BeautifulSoup

from ..context import RemoteContext
from ..models import Finding, Severity
from ..redact import shorten

CHECK = "mixed-content"

_DEFAULT = Severity.LOW
_SCRIPTISH = Severity.MEDIUM

_REMEDIATION = (
    "Load every subresource over https:// (protocol-relative // URLs are deprecated). "
    "Add `Content-Security-Policy: upgrade-insecure-requests` as a safety net."
)


def find_mixed_content(
    html: str, origin: str, *, page_is_https: bool, max_per_page: int = 6
) -> list[Finding]:
    if not page_is_https:
        return []

    soup = BeautifulSoup(html, "html.parser")
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for tag in soup.find_all(
        ["script", "iframe", "img", "link", "source", "object", "embed", "video", "audio"]
    ):
        url = tag.get("src") or tag.get("href") or tag.get("data") or ""
        if not isinstance(url, str) or not url.lower().startswith("http://"):
            continue
        key = (tag.name, url)
        if key in seen:
            continue
        seen.add(key)

        if tag.name in ("script", "iframe", "object", "embed"):
            severity = _SCRIPTISH  # script-bearing content => code execution risk
        elif tag.name == "link" and "stylesheet" in " ".join(tag.get("rel") or []).lower():
            severity = _SCRIPTISH
        else:
            severity = _DEFAULT

        findings.append(
            Finding(
                check=CHECK, severity=severity,
                title=f"Mixed content: <{tag.name}> loaded over plain http://",
                origin=origin, evidence=shorten(str(tag)[:120], 120),
                remediation=_REMEDIATION, cwe="CWE-319", location=url,
            )
        )
        if len(findings) >= max_per_page:
            break
    return findings


class MixedContentCheck:
    name = CHECK
    scope = "remote"
    description = "http:// scripts/images referenced from https:// pages"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            if page.is_https:
                findings.extend(
                    find_mixed_content(page.body, page.url, page_is_https=True)
                )
        return findings
