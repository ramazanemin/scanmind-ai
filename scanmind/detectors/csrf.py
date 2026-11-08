"""POST forms without CSRF protection.

AI builders routinely emit state-changing forms with no anti-forgery token.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ..context import RemoteContext
from ..models import Finding, Severity
from ..redact import shorten

CHECK = "csrf-forms"

CSRF_NAME = re.compile(
    r"(?i)csrf|xsrf|authenticity[_-]?token|_token|anti[_.-]?forgery|"
    r"request[_-]?token|__requestverificationtoken"
)
_ATTR_VALUE = re.compile(r"""(?i)value\s*=\s*("[^"]*"|'[^']*')""")

_REMEDIATION = (
    "Issue a per-session CSRF token and validate it server-side on every state-changing "
    "request (synchronizer token or double-submit cookie). Frameworks ship this: Django "
    "{% csrf_token %}, Laravel @csrf, express-csrf middleware."
)


def find_csrf_issues(html: str, origin: str, *, max_forms: int = 5) -> list[Finding]:
    """Find POST forms that carry no CSRF token."""
    soup = BeautifulSoup(html, "html.parser")
    page_protected = any(
        "csrf" in str(meta.get("name", "")).lower()
        for meta in soup.find_all("meta")
    )
    if page_protected:
        return []

    findings: list[Finding] = []
    for form in soup.find_all("form"):
        method = str(form.get("method") or "get").strip().lower()
        if method != "post":
            continue
        has_token = False
        for field in form.find_all(["input", "textarea"]):
            names = f"{field.get('name', '')} {field.get('id', '')}"
            if CSRF_NAME.search(names):
                has_token = True
                break
        if has_token:
            continue

        action = str(form.get("action") or "").strip() or origin
        snippet = _ATTR_VALUE.sub('value="...[redacted]"', form.decode()[:240])
        findings.append(
            Finding(
                check=CHECK, severity=Severity.MEDIUM,
                title="POST form has no CSRF token", origin=origin,
                evidence=shorten(snippet, 150), remediation=_REMEDIATION,
                cwe="CWE-352", location=f"action={action}",
            )
        )
        if len(findings) >= max_forms:
            break
    return findings


class CsrfCheck:
    name = CHECK
    scope = "remote"
    description = "State-changing (POST) forms missing anti-forgery tokens"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            findings.extend(find_csrf_issues(page.body, page.url))
        return findings
