"""Information disclosure inside HTML comments.

AI generators leave scaffolding comments behind: TODOs with passwords,
internal URLs, disabled debug blocks - all served to every visitor.
"""
from __future__ import annotations

import re

from ..context import RemoteContext
from ..models import Finding, Severity
from ..redact import line_number, shorten

CHECK = "comment-leaks"

_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_LEAK = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|passw(?:or)?d|passwd|token|credential|"
    r"private[_-]?key|debug|localhost|127\.0\.0\.1|192\.168|"
    r"todo|fixme|hard[_-]?code|test[_-]?mode)\b"
)

_REMEDIATION = (
    "Strip developer comments from deployed HTML - the browser ships them to every "
    "visitor (and they often contain credentials, internal hosts or TODO hints)."
)


def find_comment_leaks(html: str, origin: str, *, max_comments: int = 5) -> list[Finding]:
    findings: list[Finding] = []
    for match in _COMMENT.finditer(html):
        body = match.group(1)
        if not _LEAK.search(body):
            continue
        findings.append(
            Finding(
                check=CHECK, severity=Severity.INFO,
                title="Information disclosure in HTML comment", origin=origin,
                evidence=shorten(body, 140), remediation=_REMEDIATION,
                cwe="CWE-200", line=line_number(html, match.start()),
            )
        )
        if len(findings) >= max_comments:
            break
    return findings


class CommentLeaksCheck:
    name = CHECK
    scope = "remote"
    description = "Passwords / internal URLs / debug hints left in HTML comments"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in ctx.pages:
            if page.is_html:
                findings.extend(find_comment_leaks(page.body, page.url))
        return findings
