"""Probe for accidentally exposed files (.env, /.git/config, dumps, ...).

AI site builders often instruct users to "upload the whole folder" - which
puts .env files, .git metadata and SQL dumps on the public web server.
Each probe requires the response to actually look like the real file, so
SPA soft-404 catch-alls (HTTP 200 + HTML "Not Found") are not reported.
"""
from __future__ import annotations

import re

from ..context import RemoteContext
from ..models import Finding, Severity
from ..options import ScanOptions
from ..redact import redact_kv_lines, shorten


CHECK = "exposed-files"

_GIT_REM = (
    "Block this path at the web server (e.g. nginx `location ~ /\\. { deny all; }`) "
    "or remove the folder from the deployment. Assume its full content leaked - "
    "rotate every credential inside it."
)
_ENV_REM = (
    "Never deploy environment files: keep them above the web root, deny direct "
    "access in the server config, and rotate every secret that was inside."
)


def _probe(path, title, severity, requires=(), magics=(), remediation=_ENV_REM):
    return (path, title, severity, tuple(requires), tuple(magics), remediation)


PROBES = [
    _probe("/.env", "Exposed .env environment file", Severity.CRITICAL,
           requires=[re.compile(r"(?im)^[A-Z0-9_]+\s*="),
                     re.compile(r"(?i)(key|secret|pass|token|api|dsn|database)")]),
    _probe("/.env.local", "Exposed .env.local environment file", Severity.CRITICAL,
           requires=[re.compile(r"(?im)^[A-Z0-9_]+\s*="),
                     re.compile(r"(?i)(key|secret|pass|token|api|dsn|database)")]),
    _probe("/.git/config", "Exposed Git repository metadata (/.git/config)", Severity.CRITICAL,
           requires=[re.compile(r"\[core\]")], remediation=_GIT_REM),
    _probe("/.git/HEAD", "Exposed Git repository metadata (/.git/HEAD)", Severity.HIGH,
           requires=[re.compile(r"ref:")], remediation=_GIT_REM),
    _probe("/.aws/credentials", "Exposed AWS credentials file", Severity.CRITICAL,
           requires=[re.compile(r"(?i)aws_(access_key_id|secret_access_key)")],
           remediation=_GIT_REM),
    _probe("/phpinfo.php", "Exposed phpinfo() page", Severity.HIGH,
           requires=[re.compile(r"(?i)phpinfo|php version")],
           remediation="Remove phpinfo/info scripts from production."),
    _probe("/info.php", "Exposed phpinfo() page", Severity.HIGH,
           requires=[re.compile(r"(?i)phpinfo|php version")],
           remediation="Remove phpinfo/info scripts from production."),
    _probe("/db.sql", "Exposed SQL dump (db.sql)", Severity.CRITICAL,
           requires=[re.compile(r"(?i)CREATE TABLE|INSERT INTO|CREATE DATABASE")],
           remediation="Remove database dumps from the web root and rotate DB "
                       "credentials - assume the schema and its data leaked."),
    _probe("/dump.sql", "Exposed SQL dump (dump.sql)", Severity.CRITICAL,
           requires=[re.compile(r"(?i)CREATE TABLE|INSERT INTO|CREATE DATABASE")],
           remediation="Remove database dumps from the web root and rotate DB "
                       "credentials - assume the schema and its data leaked."),
    _probe("/backup.zip", "Backup archive in the web root (backup.zip)", Severity.HIGH,
           magics=[b"PK\x03\x04"],
           remediation="Never keep archives in a served directory; delete this one and "
                       "change any credentials it contains."),
    _probe("/backup.tar.gz", "Backup archive in the web root (backup.tar.gz)", Severity.HIGH,
           magics=[b"\x1f\x8b"],
           remediation="Never keep archives in a served directory; delete this one and "
                       "change any credentials it contains."),
    _probe("/.DS_Store", "Exposed .DS_Store file", Severity.LOW,
           magics=[b"\x00\x01\x00"],
           remediation="Delete the file; it leaks the directory's file names."),
]


class ExposedFilesCheck:
    name = CHECK
    scope = "remote"
    description = "Probes /.env, /.git/config, SQL dumps and other accidentally deployed files"

    def run(self, ctx: RemoteContext) -> list[Finding]:
        if ctx.fetch is None:
            return []
        options = ctx.options or ScanOptions()
        if not options.enable_probes:
            return []

        base = ctx.target
        if "://" not in base:
            base = "http://" + base
        base = base.rstrip("/")  # probe paths already start with "/"
        findings: list[Finding] = []

        for path, title, severity, requires, magics, remediation in PROBES:
            result = ctx.fetch(base + path)
            if result.status != 200 or not result.content:
                continue

            if magics:
                if not any(result.content.startswith(magic) for magic in magics):
                    continue  # soft-404 trap: 200 page that is not the real file
                evidence = f"HTTP 200, content starts with {magics[0]!r}"
            else:
                text = result.text_as("latin-1")
                if not all(rx.search(text) for rx in requires):
                    continue  # soft-404 trap
                evidence = redact_kv_lines(shorten(text, 160))

            findings.append(
                Finding(
                    check=CHECK, severity=severity, title=title,
                    origin=result.url or (base + path), evidence=evidence,
                    remediation=remediation, cwe="CWE-538", location=path,
                )
            )
        return findings
