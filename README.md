# ScanMind AI

**ScanMind AI** is a security scanner that finds the vulnerabilities
**AI-generated websites** most commonly ship. AI site builders produce
impressive results fast - and repeat the same dangerous mistakes:
working API keys pasted into client-side code, forms without CSRF
tokens, no security headers, and `.env`/`.git` folders uploaded with
the site.

Scan sites **live by URL** or audit the **generated source folder**
before it gets deployed.

```text
ScanMind AI v0.1.0 - scan report
Target : http://127.0.0.1:8907   (mode: remote)
Scope  : 3 pages/assets fetched
Checks : secrets, xss-sinks, csrf-forms, security-headers, exposed-files, comment-leaks

[CRITICAL] Exposed .env environment file
    at   : http://127.0.0.1:8907/.env
    hint : APP_NAME=...[redacted] OPENAI_API_KEY=...[redacted] DB_PASSWORD=...[redacted]
    fix  : Never deploy environment files: keep them above the web root ...

[CRITICAL] OpenAI API key (sk-...)
    at   : http://127.0.0.1:8907/ (line 24)
    hint : sk-proj-abcdefgh...[redacted]
    fix  : Revoke/rotate this key at its provider immediately ...
...
```

## Install

```bash
pip install -r requirements.txt      # or: pip install -e ".[dev]"
```

Python 3.10+ is required. The only runtime dependencies are `requests`
and `beautifulsoup4`.

## Usage

```bash
# scan a live site (same-origin crawl, depth 2, up to 8 pages)
scanmind scan https://example.com

# scan the output folder of an AI site builder before deploying it
scanmind scan ./generated-site

# machine-readable report + JSON file
scanmind scan https://example.com -f json -o report.json

# pick or skip individual checks
scanmind scan https://example.com --checks secrets,csrf-forms
scanmind scan https://example.com --skip exposed-files

# see everything the scanner knows
scanmind checks
```

`python -m scanmind scan <target>` works identically if the `scanmind`
script is not on your PATH.

### CLI options

| Flag | Meaning |
|------|---------|
| `--max-pages N` / `--max-assets N` / `--max-depth N` | crawl limits |
| `--timeout S` | per-request timeout |
| `--checks A,B` / `--skip A,B` | select/skip detectors |
| `--no-probes` | skip active probes for exposed files (`.env`, `/.git/`, ...) |
| `--insecure` | disable TLS certificate verification |
| `--user-agent S` | custom User-Agent |
| `-f json` / `-o report.json` | JSON output / save report |

### Exit codes (CI friendly)

| Code | Meaning |
|------|---------|
| `0` | scan finished, nothing at MEDIUM severity or above |
| `1` | scan finished, findings at MEDIUM severity or above |
| `2` | scan failed (bad target, network error, ...) |

## What it detects

| Check | Modes | Finds |
|-------|-------|-------|
| `secrets` | remote+local | AWS/OpenAI/Google/GitHub/Stripe/... keys, private keys, JWTs, generic `password = "..."` assignments |
| `xss-sinks` | remote+local | `eval`, `new Function`, `setTimeout("...")`, `document.write`, `.innerHTML =`, `javascript:` URLs, inline `on*` handlers |
| `csrf-forms` | remote+local | POST forms without anti-forgery tokens |
| `security-headers` | remote | missing CSP, HSTS, X-Frame-Options, nosniff, Referrer-/Permissions-Policy |
| `exposed-files` | remote | downloadable `/.env`, `/.git/config`, `/.aws/credentials`, SQL dumps, backup archives (content-verified, so SPA soft-404s are not reported) |
| `mixed-content` | remote | `http://` scripts/iframes/styles on `https://` pages |
| `comment-leaks` | remote+local | passwords, internal URLs, debug/TODO hints left in HTML comments |
| `sensitive-files` | local | `.env`, `.git/`, `.aws/`, `*.sql`, `*.zip`, ... sitting in a folder that would be deployed |

Secret evidence is always **redacted** before it is printed or stored.

## Python API

```python
from scanmind.scanner import scan_remote, scan_local, ScanOptions

result = scan_remote("https://example.com", ScanOptions(max_depth=1))
for finding in result.sorted_findings:
    print(finding.severity, finding.check, finding.title)
```

## Development

```bash
pip install -e ".[dev]"
pytest            # full suite incl. an in-memory vulnerable site + live e2e scan
```

## Legal & ethics

ScanMind AI performs **read-only GET requests** against the target and
probes a small list of well-known sensitive paths. Use it **only on
websites you own or are explicitly authorized to test**. It is a
first-pass hygiene scanner - not a replacement for a professional
pentest.

## License

MIT - see [LICENSE](LICENSE).
