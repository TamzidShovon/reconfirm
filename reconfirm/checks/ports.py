"""TCP port state for each host.

A connect() outcome maps onto the three states without any interpretation:
a completed handshake proves the port is open, a refusal proves it is closed,
and a timeout proves nothing either way.

Opt in with --checks ports. This is the only check that opens connections to
ports a browser would not, so it never runs unless asked for.
"""

NAME = "ports"
DESCRIPTION = "TCP ports accepting connections"

import socket
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


def probe(address, port, timeout=CONNECT_TIMEOUT):
    """Connect to one port. Returns (state, banner)."""
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
    # Two separate jobs, in this order.
    #
    # Collapse whitespace first. Filtering on isprintable alone drops \r and
    # \n and so glues header lines together: a real scan printed "400 Bad
    # RequestConnection: closeContent-Length" for what were three headers.
    collapsed = " ".join(text.split())
    # Then drop what is left that cannot be shown. Collapsing does not remove
    # the NUL and BEL bytes a binary protocol opens with, and those are not a
    # banner.
    return "".join(c for c in collapsed if c.isprintable())[:BANNER_BYTES]


def scan_host(address, ports, timeout=CONNECT_TIMEOUT):
    """Probe every port on one address. Returns {port: (state, banner)}."""
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        outcomes = list(pool.map(lambda p: probe(address, p, timeout), ports))
    return dict(zip(ports, outcomes))


def run(session, target, emit=None, ports=None):
    emit = emit or (lambda _msg: None)
    ports = ports or DEFAULT_PORTS
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

        outcomes = scan_host(name, ports)
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
