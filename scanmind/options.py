"""Tunables for a single scan."""
from __future__ import annotations

from dataclasses import dataclass, field

from .fetch import DEFAULT_USER_AGENT


@dataclass
class ScanOptions:
    timeout: float = 10.0
    max_pages: int = 8                 # HTML pages fetched per scan
    max_assets: int = 10               # JS/CSS assets fetched per scan
    max_depth: int = 2                 # link-follow depth
    delay: float = 0.1                 # politeness delay between requests
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    enable_probes: bool = True         # probe /.env, /.git/config, ... remotely
    run_checks: set[str] | None = None  # None = run every enabled check
    skip_checks: set[str] = field(default_factory=set)
    max_file_bytes: int = 2_000_000    # local scans: skip huge files

    def enabled(self, check_name: str) -> bool:
        if check_name in self.skip_checks:
            return False
        if self.run_checks is None:
            return True
        return check_name in self.run_checks
