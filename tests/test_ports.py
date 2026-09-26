"""TCP port probing and how each outcome is graded."""

import socket
import threading
import time

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


# --- banner readability ---

def test_multiline_banner_keeps_its_headers_apart(listener):
    # Filtering on isprintable drops \r and \n, so a three-header response
    # arrives as "400 Bad RequestConnection: closeContent-Length: 0". Seen on
    # a real router scan.
    port = listener(banner=b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
    _state, banner = ports.probe("127.0.0.1", port)
    assert "RequestConnection" not in banner
    assert "Bad Request Connection: close" in banner


def test_control_characters_are_still_removed(listener):
    # The reason the filter existed: a binary protocol's opening bytes are
    # not a banner.
    port = listener(banner=b"\x00\x01\x02ok\x07\r\n")
    _state, banner = ports.probe("127.0.0.1", port)
    assert banner.strip().endswith("ok")
    assert "\x00" not in banner and "\x07" not in banner


def test_banner_has_no_leading_or_trailing_whitespace(listener):
    port = listener(banner=b"\r\n   SSH-2.0-OpenSSH_9.6   \r\n")
    _state, banner = ports.probe("127.0.0.1", port)
    assert banner == "SSH-2.0-OpenSSH_9.6"


def test_banner_drops_unicode_that_decodes_validly(listener):
    # A binary service's opening bytes can happen to form valid multi-byte
    # UTF-8. str.isprintable() is true for that text, but it is not ASCII,
    # and the Windows console (cp1252) cannot display it - it prints as
    # mojibake instead. Seen live scanning scanme.nmap.org:9929 (nping-echo).
    port = listener(banner=b"ok\xc3\xa9tail")  # \xc3\xa9 is valid UTF-8 for "e-acute"
    _state, banner = ports.probe("127.0.0.1", port)
    assert all(ord(c) < 128 for c in banner)
    assert banner == "oktail"


# --- polite mode ---

def test_default_mode_ignores_session_delay(listener):
    # session fixture's own min_interval is 0.0; give it a slow one here and
    # confirm a fast (non-polite) scan does not honor it. Uses open listeners,
    # not refused ports: this Windows box takes ~2s to RST a refused loopback
    # connection, which would swamp the timing signal this test is after.
    port1, port2 = listener(), listener()
    scoped = Session(Scope(["127.0.0.1"]), min_interval=1.0, timeout=1.0)
    start = time.monotonic()
    ports.run(scoped, Target(domain="127.0.0.1", hosts=["127.0.0.1"]),
              ports=[port1, port2])
    assert time.monotonic() - start < 0.5


def test_polite_mode_paces_probes_by_session_delay(listener):
    port1, port2 = listener(), listener()
    scoped = Session(Scope(["127.0.0.1"]), min_interval=0.2, timeout=1.0)
    start = time.monotonic()
    ports.run(scoped, Target(domain="127.0.0.1", hosts=["127.0.0.1"]),
              ports=[port1, port2], polite=True)
    # Two probes at least one interval apart: >= 0.2s, not the sub-millisecond
    # a fast scan of two accepting ports would otherwise take.
    assert time.monotonic() - start >= 0.2


def test_polite_mode_uses_session_timeout_not_the_fast_default():
    # 192.0.2.1 is not routed, so the connection times out rather than being
    # refused. A short session timeout should cut that wait well below the
    # 3.0s CONNECT_TIMEOUT a fast scan would use.
    scoped = Session(Scope(["192.0.2.1"]), min_interval=0.0, timeout=0.3)
    start = time.monotonic()
    ports.run(scoped, Target(domain="192.0.2.1", hosts=["192.0.2.1"]),
              ports=[80], polite=True)
    assert time.monotonic() - start < 1.5


def test_scan_host_delay_serialises_instead_of_running_concurrently():
    # A concurrent pool with paced starts would still overlap; polite mode's
    # point is that the target only ever sees one connection at a time.
    seen_concurrent = []
    lock = threading.Lock()
    active = [0]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(3):
            conn, _addr = srv.accept()
            with lock:
                active[0] += 1
                seen_concurrent.append(active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        ports.scan_host("127.0.0.1", [port, port, port], delay=0.01)
    finally:
        srv.close()
        thread.join(timeout=1)

    assert max(seen_concurrent) == 1
