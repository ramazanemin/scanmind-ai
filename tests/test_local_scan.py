"""End-to-end local scan of the fixture folder (plus a .git/ created in tmp)."""
from __future__ import annotations

from scanmind.options import ScanOptions
from scanmind.scanner import scan_local


def test_local_scan_of_generated_site(local_site):
    result = scan_local(local_site, ScanOptions())

    assert result.mode == "local"
    assert result.files_scanned == 3  # index.html, contact.html, app.js
    assert {"secrets", "xss-sinks", "csrf-forms", "comment-leaks",
            "sensitive-files"}.issubset(set(result.checks_run))

    # deployment hygiene: .env and .git must be flagged
    sensitive = [f for f in result.findings if f.check == "sensitive-files"]
    origins = {f.origin for f in sensitive}
    assert ".env" in origins
    assert ".git" in origins
    assert all(f.severity.value in ("HIGH", "MEDIUM", "LOW", "CRITICAL") for f in sensitive)

    # secrets found in the generated sources, redacted in evidence
    secrets = [f for f in result.findings if f.check == "secrets"]
    assert any(f.origin == "index.html" and "OpenAI" in f.title for f in secrets)
    assert any(f.origin == "app.js" and "AWS" in f.title for f in secrets)
    for f in secrets:
        assert "abcdefghijklmnopqrstuvwxyz0123456789" not in f.evidence

    # the login form is token-less; the subscribe form is protected
    csrf = [f for f in result.findings if f.check == "csrf-forms"]
    assert any("action=/login" in f.location for f in csrf)
    assert not any("subscribe" in (f.location or "") for f in csrf)

    assert any(
        f.check == "xss-sinks" and f.origin == "app.js" and "eval()" in f.title
        for f in result.findings
    )
    assert any(f.check == "comment-leaks" for f in result.findings)
    assert result.blocking is True
