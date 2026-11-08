"""Detector registry for ScanMind AI.

Each detector is a small class exposing:

* ``name``        - stable identifier used by --checks / --skip
* ``scope``       - "remote" or "local"
* ``description`` - one-liner for `scanmind checks`
* ``run(ctx)``    - returns a list of :class:`scanmind.models.Finding`
"""
from __future__ import annotations

from .comments import CommentLeaksCheck
from .csrf import CsrfCheck
from .exposed_files import ExposedFilesCheck
from .headers import HeadersCheck
from .local import (
    LocalCommentLeaksCheck,
    LocalCsrfCheck,
    LocalSecretsCheck,
    LocalSensitiveFilesCheck,
    LocalXssCheck,
)
from .mixed_content import MixedContentCheck
from .secrets import SecretsCheck
from .xss import XssCheck

REMOTE_CHECKS = [
    SecretsCheck(),
    XssCheck(),
    CsrfCheck(),
    HeadersCheck(),
    ExposedFilesCheck(),
    MixedContentCheck(),
    CommentLeaksCheck(),
]

LOCAL_CHECKS = [
    LocalSecretsCheck(),
    LocalXssCheck(),
    LocalCsrfCheck(),
    LocalCommentLeaksCheck(),
    LocalSensitiveFilesCheck(),
]


def all_checks() -> list[dict[str, str]]:
    """Merged check catalogue for `scanmind checks`."""
    merged: dict[str, dict[str, str]] = {}
    for check in (*REMOTE_CHECKS, *LOCAL_CHECKS):
        entry = merged.setdefault(
            check.name,
            {"name": check.name, "description": check.description, "modes": ""},
        )
        modes = set(m for m in entry["modes"].split(",") if m) | {getattr(check, "scope", "")}
        entry["modes"] = "/".join(sorted(modes))
    return list(merged.values())


__all__ = [
    "REMOTE_CHECKS",
    "LOCAL_CHECKS",
    "all_checks",
    "CommentLeaksCheck",
    "CsrfCheck",
    "ExposedFilesCheck",
    "HeadersCheck",
    "MixedContentCheck",
    "SecretsCheck",
    "XssCheck",
    "LocalCommentLeaksCheck",
    "LocalCsrfCheck",
    "LocalSecretsCheck",
    "LocalSensitiveFilesCheck",
    "LocalXssCheck",
]
