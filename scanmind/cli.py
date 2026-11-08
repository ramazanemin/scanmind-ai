"""Command line interface for ScanMind AI."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .detectors import all_checks
from .fetch import DEFAULT_USER_AGENT
from .options import ScanOptions
from .report import render_console, render_json
from .scanner import scan

BANNER = (
    "ScanMind AI - finds the security vulnerabilities that AI-generated "
    "websites most commonly ship."
)


def _csv(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scanmind", description=BANNER)
    parser.add_argument("--version", action="version", version=f"ScanMind AI {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("checks", help="List all available checks")

    scan_p = sub.add_parser("scan", help="Scan a live URL or a local site folder")
    scan_p.add_argument(
        "target",
        help="URL to scan (https://example.com) or local folder (./my-site)",
    )
    scan_p.add_argument("-o", "--output", metavar="FILE",
                        help="also write a JSON report to FILE")
    scan_p.add_argument("-f", "--format", choices=("console", "json"), default="console",
                       help="output format (default: console)")
    scan_p.add_argument("--checks", metavar="A,B", help="only run these checks")
    scan_p.add_argument("--skip", metavar="A,B", help="skip these checks")
    scan_p.add_argument("--max-pages", type=int, default=8,
                        help="max HTML pages to fetch (default: 8)")
    scan_p.add_argument("--max-assets", type=int, default=10,
                        help="max JS/CSS assets to fetch (default: 10)")
    scan_p.add_argument("--max-depth", type=int, default=2,
                        help="link-follow depth (default: 2)")
    scan_p.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default: 10)")
    scan_p.add_argument("--user-agent", default=None,
                        help=f"custom User-Agent header (default: {DEFAULT_USER_AGENT})")
    scan_p.add_argument("--insecure", action="store_true",
                        help="do not verify TLS certificates")
    scan_p.add_argument("--no-probes", action="store_true",
                        help="do not actively probe /.env, /.git/config, ... (exposed files)")
    scan_p.add_argument("--no-color", action="store_true", help="disable colored output")
    return parser


def _wants_color(args) -> bool:
    if args.no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        os.system("")  # enable ANSI escape processing on Windows terminals

    args = build_parser().parse_args(argv)

    if args.command == "checks":
        print(f"ScanMind AI {__version__} - available checks\n")
        for entry in all_checks():
            print(f"  {entry['name']:<18} [{entry['modes']}]  {entry['description']}")
        print("\nUse --checks name1,name2 / --skip name1,name2 on the scan command.")
        return 0

    options = ScanOptions(
        timeout=args.timeout,
        max_pages=max(args.max_pages, 1),
        max_assets=max(args.max_assets, 1),
        max_depth=max(args.max_depth, 1),
        user_agent=args.user_agent or DEFAULT_USER_AGENT,
        verify_tls=not args.insecure,
        enable_probes=not args.no_probes,
        run_checks=_csv(args.checks) if args.checks else None,
        skip_checks=_csv(args.skip) if args.skip else set(),
    )

    try:
        result = scan(args.target, options)
    except Exception as exc:  # noqa: BLE001 - surface any failure as exit code 2
        print(f"scanmind: scan failed: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(render_json(result))
    else:
        print(render_console(result, color=_wants_color(args)))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(render_json(result))
            fh.write("\n")
        print(f"(JSON report written to {args.output})", file=sys.stderr)

    return 1 if result.blocking else 0


if __name__ == "__main__":
    sys.exit(main())
