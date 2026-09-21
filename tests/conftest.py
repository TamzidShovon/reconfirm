"""A local HTTP server the checks can be pointed at.

The rules under test are claims about behaviour against real responses, so
the fixtures serve real ones rather than mocking them.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reconfirm.net import Scope, Session


class Routes:
    """Response table for the test server."""

    def __init__(self):
        self.paths = {}
        self.catchall = (404, "text/plain", "not found")

    def add(self, path, body, status=200, ctype="text/html"):
        self.paths[path] = (status, ctype, body)
        return self

    def set_catchall(self, body, status=200, ctype="text/html"):
        self.catchall = (status, ctype, body)
        return self


class _Handler(BaseHTTPRequestHandler):
    routes = None

    def do_GET(self):
        path = self.path.split("?")[0]
        status, ctype, body = self.routes.paths.get(path, self.routes.catchall)
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    """Yields a factory: call it with Routes, get back the origin URL."""
    started = []

    def start(routes):
        handler = type("BoundHandler", (_Handler,), {"routes": routes})
        httpd = HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        started.append((httpd, thread))
        return "http://127.0.0.1:%d" % httpd.server_address[1]

    yield start

    for httpd, thread in started:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


@pytest.fixture
def session():
    """A Session scoped to loopback, with the rate limit off."""
    return Session(Scope(["127.0.0.1"]), min_interval=0.0, timeout=5)


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    from reconfirm.net import clear_lookup_cache

    clear_lookup_cache()
    yield
    clear_lookup_cache()
