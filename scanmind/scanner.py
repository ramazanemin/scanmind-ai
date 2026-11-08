"""Scan orchestration.

* :func:`scan_remote` - crawl a live site and run remote checks
* :func:`scan_local`  - read the files an AI generator produced and run local checks
* :func:`scan`        - auto-detect which mode to use for a target
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .context import LocalContext, LocalSource, RemoteContext
from .crawler import crawl
from .detectors import LOCAL_CHECKS, REMOTE_CHECKS
from .fetch import create_session, fetch
from .models import Finding, ScanResult
from .options import ScanOptions

# local mode: file types we read (mapped to a scan "kind")
SOURCE_SUFFIXES = {
    ".html": "html", ".htm": "html", ".php": "html", ".vue": "html",
    ".js": "js", ".mjs": "js", ".ts": "js", ".jsx": "js", ".tsx": "js",
}
# local mode: directories never descended into (the sensitive-files check
# flags .git/.aws/.ssh itself instead of us reading their contents)
SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".idea", ".vs", ".git", "dist", "build", ".next",
    "coverage",
}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.check, finding.origin, finding.title, finding.line, finding.location)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def scan_remote(target: str, options: ScanOptions | None = None) -> ScanResult:
    """Crawl ``target`` (same origin only) and run every remote check."""
    options = options or ScanOptions()
    raw = target.strip()
    if raw.startswith(("http://", "https://")):
        candidates = [raw]
    else:
        candidates = [f"https://{raw}", f"http://{raw}"]

    session = create_session(options.user_agent, options.verify_tls)

    start: str | None = None
    last_error = "no response"
    for candidate in candidates:
        probe = fetch(session, candidate, timeout=options.timeout)
        if probe.error:
            last_error = probe.error
            continue
        start = str(probe.url or candidate)
        break
    if start is None:
        raise RuntimeError(f"could not reach {target!r}: {last_error}")

    pages, assets = crawl(
        start,
        session,
        max_pages=options.max_pages,
        max_assets=options.max_assets,
        max_depth=options.max_depth,
        timeout=options.timeout,
        delay=options.delay,
    )

    def _fetch_polite(url: str):
        if options.delay:
            time.sleep(options.delay)
        return fetch(session, url, timeout=options.timeout)

    ctx = RemoteContext(
        target=start, pages=pages, assets=assets,
        fetch=_fetch_polite, options=options,
    )
    result = ScanResult(
        target=start, mode="remote", pages_scanned=len(pages) + len(assets)
    )
    for check in REMOTE_CHECKS:
        if not options.enabled(check.name):
            continue
        result.checks_run.append(check.name)
        result.findings.extend(check.run(ctx))
    result.findings = _dedupe(result.findings)
    return result


def scan_local(path: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Statically scan the files inside ``path`` before they get deployed."""
    options = options or ScanOptions()
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(
            f"'{path}' is not a directory - point ScanMind at a local site folder."
        )

    sources: list[LocalSource] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames):
            if name in SKIP_DIRS:
                dirnames.remove(name)
        for fname in filenames:
            fpath = Path(dirpath) / fname
            kind = SOURCE_SUFFIXES.get(fpath.suffix.lower())
            if kind is None:
                continue
            try:
                if fpath.stat().st_size > options.max_file_bytes:
                    continue
                raw = fpath.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue  # binary - not source code
            origin = fpath.relative_to(root).as_posix()
            sources.append(
                LocalSource(
                    origin=origin,
                    text=raw.decode("utf-8", errors="replace"),
                    kind=kind,
                )
            )

    ctx = LocalContext(root=root, sources=sources, options=options)
    result = ScanResult(target=str(root), mode="local", files_scanned=len(sources))
    for check in LOCAL_CHECKS:
        if not options.enabled(check.name):
            continue
        result.checks_run.append(check.name)
        result.findings.extend(check.run(ctx))
    result.findings = _dedupe(result.findings)
    return result


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Auto-detect the mode: existing local path -> local, otherwise remote."""
    candidate = str(target).strip()
    is_local = (
        candidate.startswith((".", "/", "\\", "~"))
        or os.path.isdir(candidate)
        or os.path.isfile(candidate)
    )
    if is_local:
        return scan_local(candidate, options)
    return scan_remote(candidate, options)
