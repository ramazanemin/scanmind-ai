"""Client-side XSS risk signals in HTML pages and JavaScript."""
from __future__ import annotations

import re

from ..context import RemoteContext
from ..models import Finding, Severity
from ..redact import line_number, shorten

CHECK = "xss-sinks"

# (key, title, cwe, severity, pattern, remediation)
SINKS = [
    ("js-eval", "eval() executes dynamically built strings", "CWE-95", Severity.HIGH,
     re.compile(r"\beval\s*\("),
     "Remove eval(). Use JSON.parse, function lookup maps or closures - eval of "
     "non-constant strings enables script injection and CSP bypass."),
    ("js-new-function", "new Function() builds code from strings", "CWE-95", Severity.HIGH,
     re.compile(r"\bnew\s+Function\s*\("),
     "Pass function references or use safe factories instead of new Function()."),
    ("js-timer-string", "setTimeout/setInterval called with a string argument", "CWE-95",
     Severity.HIGH,
     re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]"),
     "Pass a function reference: setTimeout(refresh, ms) - never a string."),
    ("dom-write", "document.write() injects HTML directly", "CWE-79", Severity.MEDIUM,
     re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
     "Build nodes with createElement/textContent instead of document.write()."),
    ("innerHTML-sink", "Assignment to .innerHTML with dynamic strings", "CWE-79", Severity.MEDIUM,
     re.compile(r"\.\s*innerHTML\s*=(?!=)"),
     "Use .textContent, or sanitize the HTML with DOMPurify before assigning; never "
     "concatenate untrusted input into innerHTML."),
    ("html-sink", "Assignment to .outerHTML", "CWE-79", Severity.MEDIUM,
     re.compile(r"\.\s*outerHTML\s*=(?!=)"),
     "Same risk as innerHTML - use DOM APIs or sanitize with DOMPurify."),
]

JS_URL = re.compile(r"(?i)\b(?:href|src|action|formaction)\s*=\s*['\"]\s*javascript:")
INLINE_EVENT = re.compile(r"""\son[a-z]+\s*=\s*["'][^"']*["']""")

_INLINE_REMEDIATION = (
    "Bind events with addEventListener in an external file. Inline on* attributes are "
    "dangerous when AI generators interpolate user data straight into them."
)
_JS_URL_REMEDIATION = (
    "javascript: URIs are an XSS vector; use click handlers on buttons instead."
)


def _evidence(text: str, start: int, before: int = 40, after: int = 80) -> str:
    lo = max(0, start - before)
    hi = min(len(text), start + after)
    return shorten(text[lo:hi], 160)


def find_xss_issues(
    text: str, origin: str, *, kind: str = "html", max_per_pattern: int = 3
) -> list[Finding]:
    """Find dangerous DOM/eval patterns. ``kind`` is 'html' or 'js'."""
    findings: list[Finding] = []

    for key, title, cwe, severity, pattern, remediation in SINKS:
        hits = 0
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    check=CHECK, severity=severity, title=title, origin=origin,
                    evidence=_evidence(text, match.start()), remediation=remediation,
                    cwe=cwe, line=line_number(text, match.start()),
                )
            )
            hits += 1
            if hits >= max_per_pattern:
                break

    if kind == "html":
        hits = 0
        for match in JS_URL.finditer(text):
            findings.append(
                Finding(
                    check=CHECK, severity=Severity.MEDIUM,
                    title="javascript: URI in element attribute", origin=origin,
                    evidence=_evidence(text, match.start()), remediation=_JS_URL_REMEDIATION,
                    cwe="CWE-79", line=line_number(text, match.start()),
                )
            )
            hits += 1
            if hits >= max_per_pattern:
                break

        inline = list(INLINE_EVENT.finditer(text))
        if inline:
            findings.append(
                Finding(
                    check=CHECK, severity=Severity.INFO,
                    title=f"{len(inline)} inline event handler(s) (on* attributes)",
                    origin=origin, evidence=_evidence(text, inline[0].start()),
                    remediation=_INLINE_REMEDIATION, cwe="CWE-79",
                    line=line_number(text, inline[0].start()),
                )
            )

    return findings


class XssCheck:
    name = CHECK
    scope = "remote"
    description = "eval/innerHTML/document.write sinks, javascript: URLs, inline handlers"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            findings.extend(
                find_xss_issues(page.body, page.url, kind="html" if page.is_html else "js")
            )
        for page in ctx.assets:
            findings.extend(find_xss_issues(page.body, page.url, kind="js"))
        return findings
