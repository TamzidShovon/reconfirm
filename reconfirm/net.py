"""
HTTP plumbing shared by every check: scope enforcement, rate limiting, request
budgets, and catch-all detection.

Two of these are safety rails and two are correctness tools.

Scope and budget are the rails. A recon tool aimed at the wrong host is at best
rude and at worst illegal, so the target set is fixed before any check runs and
a host that was never authorised cannot be reached even by a check with a bug
in its URL construction. The per-host budget bounds how much traffic a single
run can generate regardless of how many candidates the sources produced.

Catch-all detection is the correctness tool, and it is the single highest-value
routine in this package. A great many hosts answer 200 to literally any path —
SPAs serving index.html on every route, CDNs with a friendly 404 page, WAFs
returning a block page. Against those hosts, any check phrased as "did this
path return 200?" reports every path it tried. Probing a path that cannot exist
first, and comparing every later response against it, is what separates a real
finding from a host that says yes to everything.
"""

import random
import socket
import string
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "reconfirm/0.1 (+https://github.com/TamzidShovon/reconfirm)"

# Below this, two responses of the same content type are treated as the same
# page. Generous enough to absorb a CSRF token or a timestamp in the markup,
# tight enough that a genuinely different document is never mistaken for the
# catch-all.
CATCHALL_SIZE_TOLERANCE = 250


class OutOfScope(Exception):
    """A check tried to reach a host the run was not authorised for."""


class BudgetExhausted(Exception):
    """The per-host request budget for this run is spent."""


def _canary_path():
    tail = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    return "/__reconfirm_canary_%s__" % tail


def hostname_of(host):
    """The bare hostname from a `host`, `host:port` or `[v6]:port` string.

    Scope checks happen in two places that disagreed about this: requests go
    through urlparse, which drops the port, while a hostname read from
    --hosts-from keeps whatever the file had. A `host:port` line therefore
    matched no scope entry and was filtered out before any check ran, with
    nothing in the output but a hosts count of zero. Normalising in one place
    is what stops the two paths drifting again.
    """
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and "]" in h:
        return h[1:h.index("]")]
    # A single colon is host:port; several mean a bare IPv6 address.
    if h.count(":") == 1:
        return h.split(":")[0]
    return h


class Scope:
    """The set of registrable domains a run is allowed to touch.

    Membership is suffix-based so subdomains discovered mid-run are covered,
    but the boundary is a label boundary: "notexample.com" does not match
    "example.com". Getting that wrong is how a tool wanders onto a lookalike
    domain owned by someone else.
    """

    def __init__(self, domains):
        self.domains = {d.lower().lstrip(".").rstrip(".") for d in domains if d}

    def __contains__(self, host):
        h = hostname_of(host)
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def __iter__(self):
        return iter(sorted(self.domains))

    def __repr__(self):
        return "Scope(%s)" % ", ".join(sorted(self.domains))


class Session:
    def __init__(self, scope, min_interval=0.3, per_host_budget=200, timeout=8):
        self.scope = scope
        self.min_interval = min_interval
        self.per_host_budget = per_host_budget
        self.timeout = timeout
        self._http = requests.Session()
        self._http.verify = False
        self._http.headers.update({"User-Agent": USER_AGENT})
        self._last_request = 0.0
        self._host_counts = {}
        self._catchalls = {}

    # ── requests ──────────────────────────────────────────────────────────

    def get(self, url, **kw):
        """Rate-limited GET returning (response, error).

        Transport failures come back as an error string rather than an
        exception because for most callers a failed request is an ordinary
        inconclusive outcome, not an exceptional one — see confidence.py.
        Scope and budget violations *do* raise: those are bugs or hard stops,
        not results.
        """
        host = urlparse(url).hostname or ""
        if host not in self.scope:
            raise OutOfScope("%s is not in %r" % (host, self.scope))

        used = self._host_counts.get(host, 0)
        if used >= self.per_host_budget:
            raise BudgetExhausted(
                "%s: per-host budget of %d requests is spent" % (host, self.per_host_budget)
            )
        self._host_counts[host] = used + 1

        gap = time.time() - self._last_request
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_request = time.time()

        kw.setdefault("timeout", self.timeout)
        try:
            return self._http.get(url, **kw), None
        except Exception as e:
            return None, "%s: %s" % (type(e).__name__, e)

    def get_external(self, url, **kw):
        """GET a third-party service (crt.sh, the Wayback CDX API).

        Deliberately separate from get(): those hosts are not in scope and
        never should be, but they are also not the target, so routing them
        through the same scope check would mean either weakening the check or
        adding the world to the scope. Keeping them on their own method means
        the scope rule stays absolute for everything aimed at the target.
        """
        gap = time.time() - self._last_request
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_request = time.time()
        kw.setdefault("timeout", self.timeout)
        try:
            return self._http.get(url, **kw), None
        except Exception as e:
            return None, "%s: %s" % (type(e).__name__, e)

    # ── catch-all detection ───────────────────────────────────────────────

    def catchall(self, url):
        """Fingerprint of how an origin answers a path that cannot exist.

        Returns None when the origin was unreachable or answers the canary
        with something other than 200 — the latter being the well-behaved case,
        where a 404 means 404 and no comparison is needed. Cached per origin;
        one probe per host per run.
        """
        parsed = urlparse(url)
        origin = "%s://%s" % (parsed.scheme, parsed.netloc)
        if origin in self._catchalls:
            return self._catchalls[origin]

        info = None
        r, _err = self.get(origin + _canary_path(), allow_redirects=False)
        if r is not None and r.status_code == 200:
            info = {
                "status": r.status_code,
                "size": len(r.content),
                "ctype": r.headers.get("Content-Type", "").split(";")[0].strip().lower(),
            }
        self._catchalls[origin] = info
        return info

    def is_catchall_response(self, url, response):
        """True when this response is indistinguishable from the origin's
        answer to a path that does not exist."""
        fingerprint = self.catchall(url)
        if not fingerprint or response.status_code != 200:
            return False
        ctype = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != fingerprint["ctype"]:
            return False
        return abs(len(response.content) - fingerprint["size"]) < CATCHALL_SIZE_TOLERANCE

    def requests_made(self):
        return dict(self._host_counts)


# getaddrinfo errno values that mean the name authoritatively does not exist,
# as opposed to the resolver being unable to answer. EAI_NONAME is the POSIX
# spelling; WSAHOST_NOT_FOUND (11001) is the Windows one. Deliberately absent:
# EAI_AGAIN and WSATRY_AGAIN (11002), which are temporary failures.
_NAME_NOT_FOUND = {
    getattr(socket, "EAI_NONAME", -2),
    11001,  # WSAHOST_NOT_FOUND
}


RESOLVED = "resolved"
NXDOMAIN = "nxdomain"
UNKNOWN = "unknown"

# One lookup answers two questions -- does this name exist, and what is it
# pointing at -- and a scan asks both. Caching by name keeps --ip free rather
# than doubling every resolution.
_LOOKUP_CACHE = {}


def lookup(host):
    """Resolve a name once. Returns (addresses, state).

    state is RESOLVED, NXDOMAIN (authoritatively absent) or UNKNOWN (the
    resolver could not answer, which is not the same thing -- see resolves).
    Addresses are deduplicated and sorted, IPv4 and IPv6 together.
    """
    name = hostname_of(host)
    if not name:
        return [], NXDOMAIN
    if name in _LOOKUP_CACHE:
        return _LOOKUP_CACHE[name]

    try:
        infos = socket.getaddrinfo(name, None)
        result = (sorted({info[4][0] for info in infos}), RESOLVED)
    except socket.gaierror as e:
        result = ([], NXDOMAIN if e.errno in _NAME_NOT_FOUND else UNKNOWN)
    except Exception:
        result = ([], UNKNOWN)

    _LOOKUP_CACHE[name] = result
    return result


def clear_lookup_cache():
    """Forget every resolution.

    The cache is keyed by name and never expires, which is right for a CLI
    that resolves a host list once and exits, and wrong for anything
    long-lived or for tests that swap the resolver underneath it.
    """
    _LOOKUP_CACHE.clear()


def addresses(host):
    """Every address a name points at, or [] if it does not resolve."""
    return lookup(host)[0]


def resolves(host):
    """Whether DNS has any address record for this name.

    Worth a dedicated call because NXDOMAIN is the one transport failure that
    is not ambiguous. A timeout, a reset and a refused connection all leave
    open whether something is there; a name that does not resolve has nothing
    behind it to test, which is positive disproof and belongs in DISCARDED
    rather than inflating the unverified pile the tool exists to keep small.

    Enumerating an archive routinely yields names retired years ago, so this
    is the common case, not an edge one.
    """
    name = hostname_of(host)
    if not name:
        return False
    # Only an authoritative "no such name" counts as absence. A resolver that
    # could not answer leaves the question open, and treating the two alike
    # drops a live host from the scan on a transient blip without ever saying
    # so -- the ambiguity-as-certainty mistake this package argues against,
    # committed by the package itself. Observed: testphp.vulnweb.com was
    # silently skipped by one run and resolved fine seconds later.
    return lookup(name)[1] != NXDOMAIN


def short_error(error):
    """Condense a transport error to something a report can print.

    requests wraps urllib3 which wraps the original exception, so a DNS
    failure arrives as ~300 characters of nested repr with the pool, the URL
    and the retry count in it. None of that helps the reader decide anything.
    """
    text = str(error or "").strip()
    lowered = text.lower()
    for needle, plain in (
        ("nameresolution", "DNS did not resolve the name"),
        ("getaddrinfo", "DNS did not resolve the name"),
        ("connecttimeout", "connection timed out"),
        ("readtimeout", "the server accepted the connection then sent nothing"),
        ("timeout", "the request timed out"),
        ("sslerror", "the TLS handshake failed"),
        ("certificate", "the TLS certificate was rejected"),
        ("connectionrefused", "the connection was refused"),
        ("connectionreset", "the server reset the connection"),
        ("toomanyredirects", "the server redirected in a loop"),
    ):
        if needle in lowered.replace(" ", "").replace("_", ""):
            return plain
    return text[:140]


def fetch_site(session, host, **kw):
    """GET a hostname over HTTPS, falling back to HTTP.

    Shared by every check that starts from a bare hostname. Enumeration yields
    names, not URLs, and a meaningful share of what turns up — old staging
    boxes, appliance interfaces, the dangling hosts the takeover check exists
    to find — answers on HTTP only. Assuming HTTPS silently skips them.

    Returns (url, response, error). The URL is the one that answered, so
    callers resolve relative links against the right scheme.
    """
    last_error = ""
    for scheme in ("https", "http"):
        url = "%s://%s" % (scheme, host)
        response, error = session.get(url, **kw)
        if response is not None:
            return url, response, ""
        last_error = error
    return "https://%s" % host, None, last_error
