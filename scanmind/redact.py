"""Helpers to keep secrets out of console/JSON reports."""
from __future__ import annotations

import re

_KV_LINE = re.compile(r"([A-Za-z0-9_.\-]+)\s*[:=]\s*\S+")


def redact(value: str, keep: int = 12) -> str:
    """Show just enough of a secret to recognise it - never the whole thing."""
    value = value.strip()
    if not value:
        return "[redacted]"
    if len(value) <= keep:
        shown = value[:3]
        return f"{shown}...[redacted]"
    return f"{value[:keep]}...[redacted]"


def shorten(text: str, limit: int = 160) -> str:
    """Collapse whitespace and clip long evidence strings."""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def redact_kv_lines(text: str) -> str:
    """Redact ``KEY=value`` pairs in evidence (e.g. exposed .env files)."""
    return _KV_LINE.sub(r"\1=...[redacted]", text)


def line_number(text: str, position: int) -> int:
    """1-based line number of ``position`` inside ``text``."""
    return text.count("\n", 0, position) + 1
