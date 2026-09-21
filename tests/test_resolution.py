"""DNS resolution as a grading input, and error condensing."""

import pytest

from reconfirm.checks import Target, secrets, takeover
from reconfirm.confidence import DISCARDED, UNVERIFIED
from reconfirm.net import Scope, Session, resolves, short_error

# Reserved by RFC 2606 to never resolve.
DEAD_HOST = "nonexistent-subdomain-for-tests.invalid"


def test_loopback_resolves():
    assert resolves("127.0.0.1")


def test_invalid_tld_does_not_resolve():
    assert not resolves(DEAD_HOST)


def test_resolution_ignores_a_port():
    assert resolves("127.0.0.1:8080")


def test_empty_host_does_not_resolve():
    assert not resolves("")


@pytest.mark.parametrize("raw, expected", [
    ("ConnectionError: HTTPConnectionPool(host='x', port=80): Max retries exceeded "
     "with url: / (Caused by NameResolutionError(...getaddrinfo failed))",
     "DNS did not resolve the name"),
    ("ConnectTimeout: timed out", "connection timed out"),
    ("SSLError: certificate verify failed", "the TLS handshake failed"),
    ("ConnectionError: [Errno 111] Connection refused", "the connection was refused"),
])
def test_short_error_condenses_known_causes(raw, expected):
    assert short_error(raw) == expected


def test_short_error_truncates_anything_unrecognised():
    assert len(short_error("x" * 500)) <= 140


def test_short_error_handles_none():
    assert short_error(None) == ""


# ── grading ───────────────────────────────────────────────────────────────

@pytest.fixture
def session():
    return Session(Scope(["invalid"]), min_interval=0.0, timeout=2)


def test_takeover_discards_a_name_that_does_not_resolve(session):
    results = takeover.run(session, Target(domain="invalid", hosts=[DEAD_HOST]))
    assert [r.state for r in results] == [DISCARDED]
    assert "no address record" in results[0].reason


def test_secrets_discards_a_name_that_does_not_resolve(session):
    results = secrets.run(session, Target(domain="invalid", hosts=[DEAD_HOST]))
    assert [r.state for r in results] == [DISCARDED]


def test_a_dead_name_costs_no_requests(session):
    # An unresolvable host should not spend budget on doomed attempts.
    takeover.run(session, Target(domain="invalid", hosts=[DEAD_HOST]))
    assert session.requests_made() == {}


def test_clean_host_is_reported_rather_than_omitted(server, session):
    from tests.conftest import Routes

    routes = Routes()
    routes.add("/", '<html><script src="/app.js"></script></html>')
    routes.add("/app.js", "var greeting = 'hello';", ctype="application/javascript")
    origin = server(routes)

    local = Session(Scope(["127.0.0.1"]), min_interval=0.0, timeout=5)
    results = secrets.run(local, Target(domain="127.0.0.1", hosts=[origin.split("//")[1]]))

    # Scanned-and-clean must be visible, not silently absent.
    assert len(results) == 1
    assert results[0].state == DISCARDED
    assert "no credential material" in results[0].summary


def test_temporary_resolver_failure_is_not_treated_as_nxdomain(monkeypatch):
    # EAI_AGAIN means "ask again", not "no such name".
    import socket as _socket

    from reconfirm import net

    def temporary_failure(*_a, **_kw):
        raise _socket.gaierror(getattr(_socket, "EAI_AGAIN", 11002), "temporary failure")

    monkeypatch.setattr(net.socket, "getaddrinfo", temporary_failure)
    assert net.resolves("anything.example.com") is True


def test_authoritative_nxdomain_is_treated_as_absent(monkeypatch):
    import socket as _socket

    from reconfirm import net

    def not_found(*_a, **_kw):
        raise _socket.gaierror(getattr(_socket, "EAI_NONAME", -2), "name not known")

    monkeypatch.setattr(net.socket, "getaddrinfo", not_found)
    assert net.resolves("anything.example.com") is False


def test_windows_host_not_found_is_authoritative(monkeypatch):
    import socket as _socket

    from reconfirm import net

    def not_found(*_a, **_kw):
        raise _socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(net.socket, "getaddrinfo", not_found)
    assert net.resolves("anything.example.com") is False
