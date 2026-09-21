"""
A local HTTP server the checks can be pointed at.

The rules this package is built on are claims about behaviour against real
responses — a catch-all that answers 200 to everything, a bucket listing whose
keys belong to someone else — and asserting them against mocked request objects
would be asserting that the mocks were built correctly. A server that actually
serves the awkward responses is the only way these tests mean anything.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reconfirm.net import Scope, Session


class Routes:
    """Response table for the test server.

    `catchall` is the response for any path with no explicit route, which is
    how a SPA or a WAF behaves and the case most checks have to survive.
    """

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
    """A Session scoped to loopback, with the rate limit off.

    127.0.0.1 is in scope as a literal because Scope matching is hostname
    based and the test server has no name.
    """
    return Session(Scope(["127.0.0.1"]), min_interval=0.0, timeout=5)


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    """Resolution is cached module-wide, so one test's answer would otherwise
    be served to the next -- including to tests that swap the resolver."""
    from reconfirm.net import clear_lookup_cache

    clear_lookup_cache()
    yield
    clear_lookup_cache()
