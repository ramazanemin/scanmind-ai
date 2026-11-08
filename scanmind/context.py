"""Context objects handed to every detector."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .crawler import Page
from .fetch import FetchResult
from .options import ScanOptions


@dataclass
class RemoteContext:
    """Everything remote detectors may need."""

    target: str                                   # normalized start URL
    pages: list[Page] = field(default_factory=list)   # fetched HTML pages
    assets: list[Page] = field(default_factory=list)  # fetched JS/CSS assets
    fetch: Optional[Callable[[str], FetchResult]] = None
    options: Optional[ScanOptions] = None


@dataclass
class LocalSource:
    origin: str    # display path (relative to the scan root)
    text: str      # decoded file content
    kind: str      # "html" or "js"


@dataclass
class LocalContext:
    """Everything local-mode detectors may need."""

    root: Path
    sources: list[LocalSource] = field(default_factory=list)
    options: Optional[ScanOptions] = None
