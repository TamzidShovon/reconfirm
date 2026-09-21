"""TCP port probing and how each outcome is graded."""

import socket
import threading

import pytest

from reconfirm.checks import DEFAULT_CHECKS, Target, ports
from reconfirm.confidence import CONFIRMED, DISCARDED, UNVERIFIED
from reconfirm.net import Scope, Session

DEAD_HOST = "nonexistent-subdomain-for-tests.invalid"


@pytest.fixture
def listener():
    """A socket accepting connections; yields (port, set_banner)."""
    started = []

    def start(banner=None):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]

        def serve():
            while True:
                try:
                    conn, _addr = srv.accept()
                except OSError:
                    return
                if banner:
                    try:
                        conn.sendall(banner)
                    except OSError:
                        pass
                try:
                    conn.close()
                except OSError:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started.append(srv)
        return port

    yield start

    for srv in started:
        srv.close()


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def session():
    return Session(Scope(["127.0.0.1", "invalid"]), min_interval=0.0)


# --- probe outcomes ---

def test_open_port_is_detected(listener):
    port = listener()
    state, _banner = ports.probe("127.0.0.1", port)
    assert state == ports.OPEN


def test_refused_port_is_closed():
    state, _banner = ports.probe("127.0.0.1", _free_port())
    assert state == ports.CLOSED


def test_unroutable_address_is_filtered_not_closed():
    # TEST-NET-1 is not routed, so the connection times out rather than
    # being refused. Ambiguous, and must not read as closed.
    state, _banner = ports.probe("192.0.2.1", 80, timeout=1.0)
    assert state == ports.FILTERED


def test_banner_is_captured_when_volunteered(listener):
    port = listener(banner=b"SSH-2.0-OpenSSH_9.6\r\n")
    state, banner = ports.probe("127.0.0.1", port)
    assert state == ports.OPEN
    assert "SSH-2.0-OpenSSH_9.6" in banner


def test_no_banner_when_service_stays_quiet(listener):
    port = listener()
    _state, banner = ports.probe("127.0.0.1", port)
    assert banner == ""


def test_banner_strips_control_characters(listener):
    port = listener(banner=b"\x00\x01ok\x07\r\n")
    _state, banner = ports.probe("127.0.0.1", port)
    assert banner == "ok"


def test_banner_is_length_capped(listener):
    port = listener(banner=b"A" * 5000)
    _state, banner = ports.probe("127.0.0.1", port)
    assert len(banner) <= ports.BANNER_BYTES


# --- grading ---

def test_open_port_is_confirmed_with_evidence(listener, session):
    port = listener()
    results = ports.run(session, Target(domain="127.0.0.1", hosts=["127.0.0.1"]),
                        ports=[port])
    opened = [r for r in results if r.state == CONFIRMED]
    assert len(opened) == 1
    assert "%d/tcp open" % port in opened[0].summary
    assert "handshake completed" in opened[0].evidence


def test_closed_ports_are_discarded(session):
    results = ports.run(session, Target(domain="127.0.0.1", hosts=["127.0.0.1"]),
                        ports=[_free_port()])
    assert [r.state for r in results] == [DISCARDED]
    assert "closed" in results[0].summary


def test_filtered_ports_are_unverified_not_closed(session):
    scoped = Session(Scope(["192.0.2.1"]), min_interval=0.0)
    results = ports.run(scoped, Target(domain="192.0.2.1", hosts=["192.0.2.1"]),
                        ports=[80])
    assert [r.state for r in results] == [UNVERIFIED]
    assert "not closed" in results[0].reason


def test_unresolvable_host_is_discarded(session):
    results = ports.run(session, Target(domain="invalid", hosts=[DEAD_HOST]))
    assert [r.state for r in results] == [DISCARDED]
    assert "does not resolve" in results[0].summary


def test_out_of_scope_host_is_not_probed(session):
    results = ports.run(session, Target(domain="127.0.0.1", hosts=["example.com"]),
                        ports=[80])
    assert [r.state for r in results] == [UNVERIFIED]
    assert "not in this run's scope" in results[0].reason


def test_open_and_closed_are_reported_separately(listener, session):
    open_port = listener()
    shut_port = _free_port()
    results = ports.run(session, Target(domain="127.0.0.1", hosts=["127.0.0.1"]),
                        ports=[open_port, shut_port])
    states = [r.state for r in results]
    assert CONFIRMED in states
    assert DISCARDED in states


# --- opt-in ---

def test_ports_is_not_in_the_default_run():
    # It opens connections a browser would not, so a bare scan must not.
    assert "ports" not in DEFAULT_CHECKS


def test_ports_is_selectable_by_name():
    from reconfirm import checks

    assert checks.get(["ports"]) == [ports]


def test_default_checks_are_all_registered():
    from reconfirm import checks

    assert set(DEFAULT_CHECKS) <= set(checks.CHECKS)
