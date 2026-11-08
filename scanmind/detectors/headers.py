"""Missing security response headers on the main page."""
from __future__ import annotations

from dataclasses import dataclass

from ..context import RemoteContext
from ..models import Finding, Severity

CHECK = "security-headers"


@dataclass(frozen=True)
class HeaderSpec:
    header: str
    severity: Severity
    cwe: str
    remediation: str


SPECS: list[HeaderSpec] = [
    HeaderSpec("Content-Security-Policy", Severity.MEDIUM, "CWE-693",
               "Add a Content-Security-Policy header (start with `default-src 'self'` and "
               "loosen per feature) to contain any injected script."),
    HeaderSpec("Strict-Transport-Security", Severity.MEDIUM, "CWE-319",
               "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
               "once HTTPS is fully working."),
    HeaderSpec("X-Content-Type-Options", Severity.LOW, "CWE-79",
               "Add `X-Content-Type-Options: nosniff` so browsers never MIME-sniff "
               "uploads into executable content."),
    HeaderSpec("X-Frame-Options", Severity.LOW, "CWE-1021",
               "Prevent clickjacking: send `X-Frame-Options: SAMEORIGIN` or add "
               "`frame-ancestors 'self'` to your CSP."),
    HeaderSpec("Referrer-Policy", Severity.LOW, "CWE-200",
               "Send `Referrer-Policy: strict-origin-when-cross-origin` to avoid leaking "
               "internal URLs to third parties."),
    HeaderSpec("Permissions-Policy", Severity.INFO, "CWE-693",
               "Restrict camera/microphone/geolocation/etc. with a Permissions-Policy "
               "header."),
]


class HeadersCheck:
    name = CHECK
    scope = "remote"
    description = "CSP/HSTS/XFO and other security response headers"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        page = next((p for p in ctx.pages if p.ok and p.is_html), None)
        if page is None:
            return []

        headers = {k.lower() for k in page.headers}
        csp_value = next(
            (v for k, v in page.headers.items() if k == "content-security-policy"), ""
        )
        is_https = page.is_https

        findings: list[Finding] = []
        for spec in SPECS:
            if spec.header == "Strict-Transport-Security" and not is_https:
                continue
            if spec.header == "X-Frame-Options" and "frame-ancestors" in csp_value:
                continue
            if spec.header.lower() in headers:
                continue
            findings.append(
                Finding(
                    check=CHECK, severity=spec.severity,
                    title=f"Missing security header: {spec.header}",
                    origin=page.url,
                    evidence=f'no "{spec.header}" response header on the main page',
                    remediation=spec.remediation, cwe=spec.cwe,
                    location=spec.header,
                )
            )
        return findings
