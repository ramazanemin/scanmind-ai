"""Console and JSON report rendering."""
from __future__ import annotations

import json

from . import __version__
from .models import ALL_SEVERITIES, ScanResult, Severity

_RESET = "\033[0m"
_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[0;31m",
    Severity.MEDIUM: "\033[0;33m",
    Severity.LOW: "\033[0;36m",
    Severity.INFO: "\033[0;90m",
}


def _paint(severity: Severity, text: str, *, color: bool) -> str:
    if not color:
        return text
    return f"{_COLOR[severity]}{text}{_RESET}"


def result_to_dict(result: ScanResult) -> dict:
    return {
        "tool": "scanmind-ai",
        "version": __version__,
        "target": result.target,
        "mode": result.mode,
        "pages_scanned": result.pages_scanned,
        "files_scanned": result.files_scanned,
        "checks_run": result.checks_run,
        "counts": result.counts(),
        "findings": [f.to_dict() for f in result.sorted_findings],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(result_to_dict(result), indent=2)


def render_console(result: ScanResult, *, color: bool = False) -> str:
    out: list[str] = []

    out.append(_paint(Severity.HIGH, f"ScanMind AI v{__version__} - scan report", color=color))
    out.append(f"Target : {result.target}   (mode: {result.mode})")
    scope = result.pages_scanned if result.mode == "remote" else result.files_scanned
    unit = "pages/assets fetched" if result.mode == "remote" else "source files read"
    out.append(f"Scope  : {scope} {unit}")
    out.append(f"Checks : {', '.join(result.checks_run) if result.checks_run else 'none run'}")
    out.append("")

    findings = result.sorted_findings
    if not findings:
        out.append(
            _paint(Severity.LOW, "0 findings - no known ScanMind pattern triggered.", color=color)
        )
        out.append("")

    for f in findings:
        out.append(f"{_paint(f.severity, f'[{f.severity.value}]', color=color)} {f.title}")
        where = f.origin
        if f.line:
            where += f" (line {f.line})"
        if f.location:
            where += f" - {f.location}"
        out.append(f"    at   : {where}")
        out.append(f"    hint : {f.evidence}")
        out.append(f"    fix  : {f.remediation}")
        out.append("")

    counts = result.counts()
    parts = [f"{counts[s.value]} {s.value}" for s in ALL_SEVERITIES if counts[s.value]]
    out.append("=" * 72)
    out.append(f"Findings: {', '.join(parts) if parts else 'nothing found'}")
    if result.blocking:
        out.append(
            _paint(
                Severity.CRITICAL,
                "Verdict : FAIL - blocking findings (MEDIUM severity or above)",
                color=color,
            )
        )
    else:
        out.append(
            _paint(
                Severity.LOW,
                "Verdict : PASS - no blocking findings (clean, or LOW/INFO only)",
                color=color,
            )
        )
    out.append("=" * 72)
    out.append("Scan only websites you own or are explicitly authorized to test.")
    return "\n".join(out) + "\n"
