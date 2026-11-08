"""Shared fixtures: an in-memory 'vulnerable AI-built site' HTTP server."""
from __future__ import annotations

import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

# Tests talk to 127.0.0.1 - make sure corporate proxy env vars are ignored.
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
os.environ.setdefault("no_proxy", "127.0.0.1,localhost")

FIXTURE_SITE = Path(__file__).resolve().parent / "fixtures" / "site"


def _read(name: str) -> bytes:
    return (FIXTURE_SITE / name).read_bytes()


GIT_CONFIG = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tbare = false\n"
    b'[remote "origin"]\n'
    b"\turl = https://example.com/acme-ai-generated-site.git\n"
)

# path -> (status, {headers}, body)
ROUTES = {
    "/": (200, {"Content-Type": "text/html; charset=utf-8"}, _read("index.html")),
    "/contact": (200, {"Content-Type": "text/html; charset=utf-8"}, _read("contact.html")),
    "/app.js": (200, {"Content-Type": "application/javascript"}, _read("app.js")),
    "/.env": (200, {"Content-Type": "text/plain"}, _read(".env")),
    "/.git/config": (200, {"Content-Type": "text/plain"}, GIT_CONFIG),
    # soft-404 trap: SPA-style catch-all that answers 200 with an HTML page.
    # The exposed-files check must NOT report this.
    "/backup.zip": (
        200,
        {"Content-Type": "text/html"},
        b"<html><body>Not found page</body></html>",
    ),
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - required by http.server
        path = urlparse(self.path).path or "/"
        route = ROUTES.get(path)
        if route is None:
            self.send_error(404, "Not Found")
            return
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep pytest output clean
        return


@pytest.fixture(scope="session")
def site_url():
    """A live local HTTP server hosting the fixture site (plus probe routes)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def local_site(tmp_path):
    """Copy of the fixture site (with a .git folder) in a temp directory."""
    dest = tmp_path / "site"
    shutil.copytree(FIXTURE_SITE, dest)
    git_dir = dest / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_bytes(GIT_CONFIG)
    return dest
