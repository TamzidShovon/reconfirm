"""TCP port state for each host.

A connect() outcome maps onto the three states without any interpretation:
a completed handshake proves the port is open, a refusal proves it is closed,
and a timeout proves nothing either way.

Opt in with --checks ports. This is the only check that opens connections to
ports a browser would not, so it never runs unless asked for.

Unlike every other check, this one talks to sockets directly instead of
through Session.get(), so by default it ignores --delay and --timeout and
connects as fast as the thread pool allows. --polite makes it use the
session's timeout and space connections apart by the session's delay,
trading speed for being as gentle on the target as the other checks are.
"""

NAME = "ports"
DESCRIPTION = "TCP ports accepting connections"

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from ..confidence import confirmed, discarded, unverified
from ..net import hostname_of, resolves

# Ports worth the connection. Kept short deliberately: a full sweep is what
# nmap is for, and a long list turns an opt-in check into a loud one.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
    8888, 9200, 27017,
]

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP alt",
    8080: "HTTP alt", 8443: "HTTPS alt", 8888: "HTTP alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

MAX_PORT = 65535

# A spec naming more ports than this is almost always a typo for a range the
# user did not mean, and it turns an opt-in check into an hours-long one.
SPEC_WARN_THRESHOLD = 2000


class PortSpecError(ValueError):
    """Raised when a --ports spec cannot be parsed."""


def parse_ports(spec):
    """Turn a spec like "80,443", "1-1024" or "-" into a sorted port list.

    Accepts: a bare number, a comma-separated list, inclusive ranges, "-" or
    "all" for every port, and "top" or an empty spec for DEFAULT_PORTS.
    """
    if spec is None:
        return list(DEFAULT_PORTS)
    text = str(spec).strip().lower()
    if not text or text == "top":
        return list(DEFAULT_PORTS)
    if text in ("-", "all"):
        return list(range(1, MAX_PORT + 1))

    found = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            lo_text, _, hi_text = part.partition("-")
            lo, hi = _port(lo_text, part), _port(hi_text, part)
            if lo > hi:
                raise PortSpecError(
                    "range %r runs backwards; write it as %d-%d" % (part, hi, lo)
                )
            found.update(range(lo, hi + 1))
        else:
            found.add(_port(part, part))

    if not found:
        raise PortSpecError("no ports in spec %r" % spec)
    return sorted(found)


def _port(text, context):
    text = text.strip()
    if not text.isdigit():
        raise PortSpecError("%r in %r is not a port number" % (text, context))
    value = int(text)
    if not 1 <= value <= MAX_PORT:
        raise PortSpecError("port %d in %r is outside 1-%d" % (value, context, MAX_PORT))
    return value


OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

CONNECT_TIMEOUT = 3.0
BANNER_TIMEOUT = 1.5
BANNER_BYTES = 120
WORKERS = 16


class _Pacer:
    """Serialises probe start times to at least `interval` seconds apart.

    An HTTP check gets this for free from Session.get(); a raw socket
    connect has no shared queue to throttle, so polite mode gives ports
    the same gate by hand.
    """

    def __init__(self, interval):
        self.interval = interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        with self._lock:
            gap = time.monotonic() - self._last
            if gap < self.interval:
                time.sleep(self.interval - gap)
            self._last = time.monotonic()


def probe(address, port, timeout=CONNECT_TIMEOUT, pacer=None):
    """Connect to one port. Returns (state, banner)."""
    if pacer is not None:
        pacer.wait()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except socket.timeout:
        return FILTERED, ""
    except ConnectionRefusedError:
        # An RST is the host saying nothing listens here.
        return CLOSED, ""
    except OSError:
        # Unreachable, reset by a middlebox, or refused by the local stack.
        # Only an explicit refusal is evidence; everything else is ambiguous.
        return FILTERED, ""
    else:
        return OPEN, _banner(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _banner(sock):
    """Read what a service volunteers on connect, without sending anything."""
    sock.settimeout(BANNER_TIMEOUT)
    try:
        data = sock.recv(BANNER_BYTES)
    except (socket.timeout, OSError):
        return ""
    text = data.decode("utf-8", "replace")
    # Three separate jobs, in this order.
    #
    # Collapse whitespace first. Filtering on printability alone drops \r and
    # \n and so glues header lines together: a real scan printed "400 Bad
    # RequestConnection: closeContent-Length" for what were three headers.
    collapsed = " ".join(text.split())
    # Then drop what is left that cannot be shown. Collapsing does not remove
    # the NUL and BEL bytes a binary protocol opens with, and those are not a
    # banner.
    printable = "".join(c for c in collapsed if c.isprintable())
    # Finally, restrict to ASCII. A binary service (scanme.nmap.org's
    # nping-echo on 9929, seen live) fills its greeting with bytes that
    # happen to form valid multi-byte UTF-8 - str.isprintable() is true for
    # that Unicode, but the Windows console is cp1252 and cannot show it.
    return printable.encode("ascii", "ignore").decode("ascii")[:BANNER_BYTES]


def scan_host(address, ports, timeout=CONNECT_TIMEOUT, delay=0.0, workers=WORKERS):
    """Probe every port on one address. Returns {port: (state, banner)}.

    delay=0 (the default) fires every probe as fast as the thread pool
    allows. delay>0 paces probe starts that far apart and runs them one at a
    time, since spacing out starts within a still-concurrent pool would not
    actually bound the rate the target sees.
    """
    pacer = _Pacer(delay) if delay > 0 else None
    effective_workers = 1 if pacer else workers
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        outcomes = list(pool.map(lambda p: probe(address, p, timeout, pacer), ports))
    return dict(zip(ports, outcomes))


def run(session, target, emit=None, ports=None, polite=False):
    """polite=True makes this check behave like the others: it uses the
    session's --timeout and --delay instead of connecting as fast as
    possible. Default is fast, since a scan the user explicitly opted into
    is not the case --delay was built to protect against.
    """
    emit = emit or (lambda _msg: None)
    ports = ports or DEFAULT_PORTS
    timeout = session.timeout if polite else CONNECT_TIMEOUT
    delay = session.min_interval if polite else 0.0
    results = []

    for host in target.hosts:
        name = hostname_of(host)
        if name not in session.scope:
            results.append(
                unverified(NAME, host, "not probed", "%s is not in this run's scope" % name)
            )
            continue
        if not resolves(name):
            results.append(
                discarded(
                    NAME, host, "name does not resolve",
                    "DNS has no address record for this name, so there is nothing "
                    "to connect to",
                )
            )
            continue

        outcomes = scan_host(name, ports, timeout=timeout, delay=delay)
        opened = [p for p, (state, _b) in outcomes.items() if state == OPEN]
        closed = [p for p, (state, _b) in outcomes.items() if state == CLOSED]
        filtered = [p for p, (state, _b) in outcomes.items() if state == FILTERED]

        for port in sorted(opened):
            _state, banner = outcomes[port]
            service = SERVICES.get(port, "unknown service")
            evidence = "TCP handshake completed on %d" % port
            if banner:
                evidence += " | banner: %s" % banner
            results.append(
                confirmed(
                    NAME, "%s:%d" % (name, port),
                    "%d/tcp open (%s)" % (port, service),
                    evidence=evidence,
                )
            )
        if opened:
            emit("  %s: %s open" % (name, ", ".join(str(p) for p in sorted(opened))))

        if closed:
            results.append(
                discarded(
                    NAME, name,
                    "%d of %d ports closed" % (len(closed), len(ports)),
                    "the host refused the connection on each, which is positive "
                    "evidence that nothing is listening",
                )
            )
        if filtered:
            results.append(
                unverified(
                    NAME, name,
                    "%d of %d ports did not answer" % (len(filtered), len(ports)),
                    "no response before the timeout, which a firewall, a rate "
                    "limiter and a slow host all produce identically - unknown, "
                    "not closed",
                )
            )

    return results
