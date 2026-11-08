"""Local-mode scanners: audit the files an AI generator produced pre-deploy."""
from __future__ import annotations

import os

from ..context import LocalContext
from ..models import Finding, Severity
from .comments import find_comment_leaks
from .csrf import find_csrf_issues
from .secrets import find_secrets
from .xss import find_xss_issues

_ENV_REM = (
    "This file must never be uploaded: keep it outside the deployed folder, add a "
    "server deny rule, and rotate every secret inside if it was ever public."
)


class LocalSecretsCheck:
    name = "secrets"
    scope = "local"
    description = "Hard-coded API keys, tokens and private keys in source files"

    def run(self, ctx: LocalContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.sources:
            findings.extend(find_secrets(source.text, source.origin))
        return findings


class LocalXssCheck:
    name = "xss-sinks"
    scope = "local"
    description = "eval/innerHTML/document.write sinks in source files"

    def run(self, ctx: LocalContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.sources:
            findings.extend(find_xss_issues(source.text, source.origin, kind=source.kind))
        return findings


class LocalCsrfCheck:
    name = "csrf-forms"
    scope = "local"
    description = "State-changing (POST) forms missing anti-forgery tokens"

    def run(self, ctx: LocalContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.sources:
            if source.kind == "html":
                findings.extend(find_csrf_issues(source.text, source.origin))
        return findings


class LocalCommentLeaksCheck:
    name = "comment-leaks"
    scope = "local"
    description = "Passwords / internal URLs / debug hints left in HTML comments"

    def run(self, ctx: LocalContext) -> list[Finding]:
        findings: list[Finding] = []
        for source in ctx.sources:
            if source.kind == "html":
                findings.extend(find_comment_leaks(source.text, source.origin))
        return findings


CHECK = "sensitive-files"

# directories that must never ship with a website
SENSITIVE_DIRS = {
    ".git": ("Git repository folder (.git) in the deploy folder", Severity.HIGH),
    ".svn": ("Subversion metadata (.svn) in the deploy folder", Severity.MEDIUM),
    ".aws": ("AWS credentials folder (.aws) in the deploy folder", Severity.HIGH),
    ".ssh": (".ssh folder in the deploy folder", Severity.HIGH),
}
SENSITIVE_FILENAMES = {
    ".env": ("Environment file (.env) would be deployed with the site", Severity.HIGH),
    ".env.local": ("Environment file (.env.local) would be deployed with the site", Severity.HIGH),
    ".env.production": ("Environment file (.env.production) would be deployed with the site", Severity.HIGH),
    ".env.development": ("Environment file (.env.development) would be deployed with the site", Severity.MEDIUM),
    ".env.backup": ("Environment file backup (.env.backup) would be deployed", Severity.HIGH),
    ".htpasswd": ("Apache password file (.htpasswd) would be deployed", Severity.CRITICAL),
    ".DS_Store": ("macOS .DS_Store metadata in the deploy folder", Severity.LOW),
    "Thumbs.db": ("Windows Thumbs.db thumbnail cache in the deploy folder", Severity.LOW),
}
SENSITIVE_SUFFIXES = {
    ".sql": ("SQL dump in the deploy folder", Severity.HIGH),
    ".zip": ("Archive in the deploy folder", Severity.MEDIUM),
    ".tar": ("Archive in the deploy folder", Severity.MEDIUM),
    ".gz": ("Archived file in the deploy folder", Severity.MEDIUM),
    ".bak": ("Backup file in the deploy folder", Severity.MEDIUM),
    ".old": ("Old file version in the deploy folder", Severity.LOW),
    ".orig": ("Merge artifact in the deploy folder", Severity.LOW),
    ".swp": ("Vim swap file in the deploy folder", Severity.LOW),
}
# never descend into these (dev artifacts, not deployment findings)
SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".idea", ".vs", "dist", "build", ".next", "coverage",
}


class LocalSensitiveFilesCheck:
    name = CHECK
    scope = "local"
    description = "Files/directories that must never be deployed (.env, .git, dumps, archives)"

    def run(self, ctx: LocalContext, *, max_findings: int = 15) -> list[Finding]:
        root = str(ctx.root)
        findings: list[Finding] = []
        seen: set[str] = set()

        def flag(rel_path: str, title: str, severity: Severity) -> None:
            rel = os.path.normpath(rel_path).replace(os.sep, "/")
            if rel in seen or len(findings) >= max_findings:
                return
            seen.add(rel)
            findings.append(
                Finding(
                    check=CHECK, severity=severity, title=title, origin=rel,
                    evidence="present in the folder that would be uploaded to the web server",
                    remediation=_ENV_REM, cwe="CWE-538",
                )
            )

        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            for name in list(dirnames):
                if name in SKIP_DIRS:
                    dirnames.remove(name)
                    continue
                spec = SENSITIVE_DIRS.get(name)
                if spec is not None:
                    flag(os.path.join(rel_dir, name), spec[0], spec[1])
                    dirnames.remove(name)  # do not walk into it
            for fname in filenames:
                lowered = fname.lower()
                spec = SENSITIVE_FILENAMES.get(lowered)
                if spec is None:
                    spec = next(
                        (s for suf, s in SENSITIVE_SUFFIXES.items() if lowered.endswith(suf)),
                        None,
                    )
                if spec is not None:
                    flag(os.path.join(rel_dir, fname), spec[0], spec[1])
        return findings
