"""The scope rail, request budgets, and catch-all detection."""

import pytest

from reconfirm.net import BudgetExhausted, OutOfScope, Scope, Session
from tests.conftest import Routes


# --- scope ---

@pytest.mark.parametrize("host, inside", [
    ("example.com", True),
    ("api.example.com", True),
    ("deep.nested.example.com", True),
    ("EXAMPLE.COM", True),
    ("example.com.", True),
    ("notexample.com", False),
    ("example.com.evil.net", False),
    ("example.org", False),
    ("", False),
])
def test_scope_matches_on_label_boundaries(host, inside):
    # Plain suffix matching would place "notexample.com" inside it.
    assert (host in Scope(["example.com"])) is inside


def test_out_of_scope_raises_rather_than_returning_an_error():
    # A scope violation is a bug, not a result.
    session = Session(Scope(["example.com"]), min_interval=0.0)
    with pytest.raises(OutOfScope):
        session.get("https://evil.net/")


def test_budget_is_enforced_per_host(server):
    routes = Routes().add("/", "ok")
    origin = server(routes)
    session = Session(Scope(["127.0.0.1"]), min_interval=0.0, per_host_budget=3)

    for _ in range(3):
        session.get(origin + "/")
    with pytest.raises(BudgetExhausted):
        session.get(origin + "/")


def test_transport_failure_returns_an_error_not_an_exception():
    session = Session(Scope(["127.0.0.1"]), min_interval=0.0, timeout=1)
    response, error = session.get("http://127.0.0.1:1/")
    assert response is None
    assert error


# --- catch-all detection ---

def test_catchall_detected_when_every_path_returns_200(server, session):
    routes = Routes().set_catchall("<html><body>app shell</body></html>")
    origin = server(routes)

    fingerprint = session.catchall(origin + "/")
    assert fingerprint is not None
    assert fingerprint["status"] == 200


def test_no_catchall_on_a_host_that_returns_404(server, session):
    routes = Routes().add("/", "<html>home</html>")
    origin = server(routes)

    assert session.catchall(origin + "/") is None


def test_response_matching_the_catchall_is_recognised(server, session):
    routes = Routes().set_catchall("<html><body>app shell</body></html>")
    origin = server(routes)

    response, _ = session.get(origin + "/.env")
    assert session.is_catchall_response(origin + "/.env", response)


def test_genuinely_different_response_is_not_the_catchall(server, session):
    routes = Routes().set_catchall("<html><body>app shell</body></html>")
    routes.add("/.env", "DB_PASSWORD=hunter2\nAPI_KEY=abcdef\n" + "x" * 500,
               ctype="text/plain")
    origin = server(routes)

    response, _ = session.get(origin + "/.env")
    assert not session.is_catchall_response(origin + "/.env", response)


def test_catchall_probed_once_per_origin(server, session):
    routes = Routes().set_catchall("<html>shell</html>")
    origin = server(routes)

    session.catchall(origin + "/a")
    before = session.requests_made()["127.0.0.1"]
    session.catchall(origin + "/b")
    assert session.requests_made()["127.0.0.1"] == before
