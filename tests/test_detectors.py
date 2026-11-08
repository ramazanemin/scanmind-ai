"""Unit tests for the pure detector functions."""
from __future__ import annotations

from scanmind.context import RemoteContext
from scanmind.crawler import Page
from scanmind.detectors.comments import find_comment_leaks
from scanmind.detectors.csrf import find_csrf_issues
from scanmind.detectors.headers import HeadersCheck
from scanmind.detectors.mixed_content import find_mixed_content
from scanmind.detectors.secrets import find_secrets
from scanmind.detectors.xss import find_xss_issues
from scanmind.options import ScanOptions


def test_finds_openai_key_and_redacts_it():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    text = f'const OPENAI_API_KEY = "{secret}";'
    findings = find_secrets(text, "index.html")
    assert any("OpenAI" in f.title for f in findings)
    for f in findings:
        assert secret not in f.evidence, "the full key must never appear in evidence"
        assert "abcdefghijklmnopqrstuvwxyz" not in f.evidence
    assert findings[0].line is not None


def test_finds_aws_keys_and_private_key_material():
    text = (
        'const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";\n'
        "-----BEGIN RSA PRIVATE KEY-----\nmIIabc\n-----END RSA PRIVATE KEY-----\n"
    )
    findings = find_secrets(text, "app.js")
    assert any("AWS access key ID" in f.title for f in findings)
    assert any("Private key" in f.title for f in findings)


def test_generic_credential_but_not_urls_or_variants():
    text = (
        'const authToken = "s3cr3t-t0ken-xyz12";\n'
        'const docsUrl = "https://docs.example.com/page?t=1";\n'
        "var password = 12345;\n"
    )
    findings = find_secrets(text, "a.js")
    generic = [f for f in findings if f.title == "Hard-coded credential-like assignment"]
    assert len(generic) == 1
    assert generic[0].evidence.startswith("authToken = s3cr3t-t")  # short prefix shown
    assert "s3cr3t-t0ken-xyz12" not in generic[0].evidence  # but never the whole thing
    assert not any("example.com" in f.evidence for f in findings)


def test_finds_google_api_key():
    text = 'const mapKey = "AIzaSy0123456789abcdefghijABCDEFGHIJ123";'
    findings = find_secrets(text, "index.html")
    assert any("Google API key" in f.title for f in findings)
    for f in findings:
        assert "AIzaSy0123456789abcdefghij" not in f.evidence  # redacted


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = find_secrets(f'var session = "{jwt}";', "a.js")
    assert any("JSON Web Token" in f.title for f in findings)


def test_csrf_forms():
    good = ('<form method="post" action="/save">'
            '<input type="hidden" name="csrf_token" value="abc"></form>')
    bad = '<form method="POST" action="/login"><input name="username"></form>'
    get_form = '<form action="/search"><input name="q"></form>'

    assert find_csrf_issues(good, "p.html") == []
    assert find_csrf_issues(get_form, "p.html") == []
    findings = find_csrf_issues(bad, "p.html")
    assert len(findings) == 1
    assert "action=/login" in findings[0].location


def test_xss_sinks_and_inline_handlers():
    html = '<a href="javascript:void(0)">go</a>'
    assert any("javascript:" in f.title for f in find_xss_issues(html, "p.html", kind="html"))
    assert any(
        "inline event handler" in f.title
        for f in find_xss_issues('<div onclick="go()">x</div>', "p.html", kind="html")
    )

    js = 'eval("x"); document.write("<b>hi</b>"); el.innerHTML = "<i>" + user + "</i>"; el.innerHTML !== other;'
    js_findings = find_xss_issues(js, "a.js", kind="js")
    titles = [f.title for f in js_findings]
    assert any("eval()" in t for t in titles)
    assert any("document.write()" in t for t in titles)
    assert len([t for t in titles if "innerHTML" in t]) == 1  # !== is not a sink


def test_mixed_content_only_on_https_pages():
    html = ('<script src="http://cdn.example.com/x.js"></script>'
            '<img src="http://cdn.example.com/i.png">')
    https_findings = find_mixed_content(html, "https://site.test/", page_is_https=True)
    assert {f.severity.value for f in https_findings} == {"MEDIUM", "LOW"}

    assert find_mixed_content(html, "http://site.test/", page_is_https=False) == []


def test_comment_leaks():
    html = "<!-- TODO: remove admin password hunter2 --> <!-- just a comment -->"
    findings = find_comment_leaks(html, "p.html")
    assert len(findings) == 1
    assert "admin password" in findings[0].evidence


def _page(url: str, headers: dict) -> Page:
    return Page(url=url, status=200, headers=headers, content_type="text/html",
                body="<html></html>", ok=True)


def test_security_headers_check():
    ctx = RemoteContext(
        target="https://x.test/",
        pages=[_page("https://x.test/", {"content-type": "text/html"})],
        assets=[], fetch=None, options=ScanOptions(),
    )
    findings = HeadersCheck().run(ctx)
    names = {f.location for f in findings}
    assert "Content-Security-Policy" in names
    assert "Strict-Transport-Security" in names
    assert len(findings) == 6

    clean_headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    ctx_ok = RemoteContext(
        target="https://x.test/",
        pages=[_page("https://x.test/", clean_headers)],
        assets=[], fetch=None, options=ScanOptions(),
    )
    assert HeadersCheck().run(ctx_ok) == []
