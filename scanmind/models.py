"""Core data models shared across ScanMind AI."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity of a detected issue. Higher rank means worse."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def __str__(self) -> str:
        return self.value


_RANKS = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

ALL_SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True)
class Finding:
    """A single issue detected by a ScanMind check."""

    check: str                 # detector name, e.g. "secrets", "csrf-forms"
    severity: Severity
    title: str                 # short human-readable description
    origin: str                # URL (remote scans) or file path (local scans)
    evidence: str              # redacted snippet proving the finding
    remediation: str           # how to fix it
    location: str = ""         # extra context (header name, form action, ...)
    cwe: str = ""              # weakness classification, e.g. "CWE-798"
    line: int | None = None    # 1-based line number in origin, when known

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "title": self.title,
            "origin": self.origin,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "location": self.location,
            "cwe": self.cwe,
            "line": self.line,
        }


@dataclass
class ScanResult:
    """Everything a single scan produced."""

    target: str
    mode: str                                   # "remote" or "local"
    pages_scanned: int = 0
    files_scanned: int = 0
    checks_run: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.check, f.origin))

    def counts(self) -> dict[str, int]:
        base = {s.value: 0 for s in ALL_SEVERITIES}
        for finding in self.findings:
            base[finding.severity.value] += 1
        return base

    @property
    def blocking(self) -> bool:
        """True when any finding is MEDIUM severity or above."""
        return any(f.severity.rank >= Severity.MEDIUM.rank for f in self.findings)
