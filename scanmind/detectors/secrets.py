"""Detect hard-coded secrets in served HTML or JavaScript.

AI site builders love to paste working API keys straight into client-side
code ("add your key here" - and users do). This detector finds them and
redacts the evidence before it ends up in a report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..context import RemoteContext
from ..models import Finding, Severity
from ..redact import line_number, redact, shorten

CHECK = "secrets"

_ROTATE = (
    "Revoke/rotate this key at its provider immediately - it ships with the public "
    "website code. Call the API from a backend proxy instead of the browser."
)
_MOVE_SECRET = (
    "Never hard-code credentials. Read them from server-side environment variables "
    "and keep them out of anything the browser can download."
)


@dataclass(frozen=True)
class SecretPattern:
    key: str
    title: str
    cwe: str
    severity: Severity
    pattern: re.Pattern[str]
    remediation: str


PATTERNS: list[SecretPattern] = [
    SecretPattern("aws-access-key", "AWS access key ID (AKIA...)", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\bAKIA[0-9A-Z]{16}\b"), _ROTATE),
    SecretPattern("aws-secret-key", "AWS secret access key", "CWE-798", Severity.CRITICAL,
                  re.compile(r"(?i)aws[^\n]{0,40}secret[^\n]{0,30}['\"]"
                             r"[0-9a-zA-Z/+]{40}['\"]"), _ROTATE),
    SecretPattern("openai-key", "OpenAI API key (sk-...)", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b"), _ROTATE),
    SecretPattern("google-api-key", "Google API key (AIza...)", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
                  "Restrict the key by HTTP referrer in Google Cloud Console, rotate it, "
                  "and call Google APIs from your backend."),
    SecretPattern("github-token", "GitHub access token (gh..._)", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), _ROTATE),
    SecretPattern("gitlab-token", "GitLab access token (glpat-...)", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), _ROTATE),
    SecretPattern("slack-token", "Slack token (xox...)", "CWE-798", Severity.HIGH,
                  re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), _ROTATE),
    SecretPattern("stripe-live-key", "Stripe LIVE secret key", "CWE-798", Severity.CRITICAL,
                  re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b"), _ROTATE),
    SecretPattern("stripe-test-key", "Stripe test key shipped to the browser", "CWE-798", Severity.LOW,
                  re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{16,}\b"),
                  "Test keys are not exploitable but should still live server-side only."),
    SecretPattern("sendgrid-key", "SendGrid API key (SG....)", "CWE-798", Severity.HIGH,
                  re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), _ROTATE),
    SecretPattern("twilio-key", "Twilio API key (SK...)", "CWE-798", Severity.HIGH,
                  re.compile(r"\bSK[0-9a-fA-F]{32}\b"), _ROTATE),
]

PATTERNS.extend([
    SecretPattern("private-key", "Private key material (-----BEGIN ... PRIVATE KEY-----)",
                  "CWE-798", Severity.CRITICAL,
                  re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?"
                             r"PRIVATE KEY(?: BLOCK)?-----"), _ROTATE),
    SecretPattern("jwt", "Hard-coded JSON Web Token", "CWE-798", Severity.HIGH,
                  re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
                  "Any JWT embedded in a page is effectively public. Move session or API "
                  "tokens to HTTP-only cookies or server-side storage."),
])

# key-name = "value"-style assignments (less specific, gated by exclusions below)
GENERIC_CREDENTIAL = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|pwd|token|access[_-]?token|"
    r"auth[_-]?token|client[_-]?secret)\b['\"]?\s*[=:]\s*['\"]([^'\"`<>\s]{12,})['\"]"
)
_GENERIC_EXCLUDE = re.compile(
    r"^(?:https?://|#|//|[\d.\-]+$|\$\{|\{\{|%\(|0x[0-9a-fA-F]+$|rgba?\()"
)


def find_secrets(text: str, origin: str, *, max_per_pattern: int = 3) -> list[Finding]:
    """Scan ``text`` for embedded secrets. Evidence is always redacted."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for spec in PATTERNS:
        hits = 0
        for match in spec.pattern.finditer(text):
            snippet = match.group(0)
            key = (spec.key, snippet)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    check=CHECK, severity=spec.severity, title=spec.title, origin=origin,
                    evidence=redact(shorten(snippet, 120), keep=12),
                    remediation=spec.remediation, cwe=spec.cwe,
                    line=line_number(text, match.start()),
                )
            )
            hits += 1
            if hits >= max_per_pattern:
                break

    generic_hits = 0
    for match in GENERIC_CREDENTIAL.finditer(text):
        value = match.group(2)
        if _GENERIC_EXCLUDE.match(value):
            continue
        if any(spec.pattern.search(value) for spec in PATTERNS):
            continue  # already reported by a more specific pattern above
        dedupe_key = ("generic-credential", value)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(
            Finding(
                check=CHECK, severity=Severity.MEDIUM,
                title="Hard-coded credential-like assignment",
                origin=origin,
                evidence=f"{match.group(1)} = {redact(value, keep=8)}",
                remediation=_MOVE_SECRET, cwe="CWE-798",
                line=line_number(text, match.start()),
            )
        )
        generic_hits += 1
        if generic_hits >= max_per_pattern:
            break

    return findings


class SecretsCheck:
    name = CHECK
    scope = "remote"
    description = "Hard-coded API keys, tokens and private keys in served HTML/JS"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in [*ctx.pages, *ctx.assets]:
            findings.extend(find_secrets(page.body, page.url))
        return findings

