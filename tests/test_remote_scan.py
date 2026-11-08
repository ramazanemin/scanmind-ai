"""End-to-end remote scan against the in-memory vulnerable site."""
from __future__ import annotations

from scanmind.options import ScanOptions
from scanmind.scanner import scan_remote


def test_remote_scan_of_vulnerable_site(site_url):
    result = scan_remote(site_url, ScanOptions(delay=0.0, timeout=5, max_pages=10))

    assert result.mode == "remote"
    assert result.pages_scanned >= 3  # /, /contact, /app.js
    assert {"secrets", "xss-sinks", "csrf-forms", "security-headers",
            "exposed-files", "comment-leaks"}.issubset(set(result.checks_run))

    # --- secrets (redacted) ------------------------------------------------
    secrets = [f for f in result.findings if f.check == "secrets"]
    titles = " | ".join(f.title for f in secrets)
    assert "OpenAI" in titles
    assert "AWS" in titles                       # from /app.js
    assert "Google API key" in titles            # from the HTML comment
    for f in secrets:
        assert "abcdefghijklmnopqrstuvwxyz0123456789" not in f.evidence
        assert "wJalrXUtnFEMI" not in f.evidence

    # --- csrf --------------------------------------------------------------
    csrf = [f for f in result.findings if f.check == "csrf-forms"]
    assert any("action=/login" in f.location for f in csrf)
    assert not any("subscribe" in (f.location or "") for f in csrf)  # protected form passes

    # --- exposed files -----------------------------------------------------
    exposed = [f for f in result.findings if f.check == "exposed-files"]
    env = next(f for f in exposed if f.origin.endswith("/.env"))
    assert env.severity.value == "CRITICAL"
    assert "sk-proj-abcdefgh" not in env.evidence  # env values redacted
    assert any(f.origin.endswith("/.git/config") for f in exposed)
    assert not any("backup.zip" in f.origin for f in exposed)  # soft-404 not reported

    # --- headers -----------------------------------------------------------
    headers = [f for f in result.findings if f.check == "security-headers"]
    assert any("Content-Security-Policy" in f.title for f in headers)
    assert not any("Strict-Transport-Security" in f.title for f in headers)  # http:// target

    # --- xss & comments ----------------------------------------------------
    xss = [f for f in result.findings if f.check == "xss-sinks"]
    assert any("eval()" in f.title for f in xss)
    assert any("innerHTML" in f.title for f in xss)
    assert any("javascript:" in f.title for f in xss)

    comments = [f for f in result.findings if f.check == "comment-leaks"]
    assert any("admin password" in f.evidence for f in comments)

    # no https anywhere -> no mixed content findings at all
    assert not [f for f in result.findings if f.check == "mixed-content"]

    assert result.blocking is True
