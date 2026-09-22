"""HTTP plumbing shared by every check.

Scope enforcement and per-host request budgets bound what a run can reach.
Catch-all detection fingerprints how an origin answers a path that cannot
exist, so checks can tell a real response from a host that returns 200 for
everything.
"""

import ipaddress
import random
import socket
import string
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "reconfirm/0.1 (+https://github.com/TamzidShovon/reconfirm)"

# Below this, two responses of the same content type are the same page.
CATCHALL_SIZE_TOLERANCE = 250


class OutOfScope(Exception):
    """A check tried to reach a host the run was not authorised for."""


class BudgetExhausted(Exception):
    """The per-host request budget for this run is spent."""


def _canary_path():
    tail = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    return "/__reconfirm_canary_%s__" % tail


def is_ip_literal(host):
    """True when this is an address rather than a name."""
    try:
        ipaddress.ip_address(hostname_of(host).strip("[]"))
    except ValueError:
        return False
    return True


def hostname_of(host):
    """The bare hostname from a `host`, `host:port` or `[v6]:port` string."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and "]" in h:
        return h[1:h.index("]")]
    # A single colon is host:port; several mean a bare IPv6 address.
    if h.count(":") == 1:
        return h.split(":")[0]
    return h


class Scope:
    """The registrable domains a run is allowed to touch."""

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

    # --- requests ---

    def get(self, url, **kw):
        """Rate-limited GET returning (response, error)."""
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
        """GET a third-party service (crt.sh, the Wayback CDX API)."""
        gap = time.time() - self._last_request
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_request = time.time()
        kw.setdefault("timeout", self.timeout)
        try:
            return self._http.get(url, **kw), None
        except Exception as e:
            return None, "%s: %s" % (type(e).__name__, e)

    # --- catch-all detection ---

    def catchall(self, url):
        """Fingerprint of how an origin answers a path that cannot exist."""
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
        """True when this response matches the origin's catch-all page."""
        fingerprint = self.catchall(url)
        if not fingerprint or response.status_code != 200:
            return False
        ctype = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != fingerprint["ctype"]:
            return False
        return abs(len(response.content) - fingerprint["size"]) < CATCHALL_SIZE_TOLERANCE

    def requests_made(self):
        return dict(self._host_counts)


# getaddrinfo errno values meaning the name authoritatively does not exist.
# EAI_AGAIN and WSATRY_AGAIN are excluded: those are temporary failures.
_NAME_NOT_FOUND = {
    getattr(socket, "EAI_NONAME", -2),
    11001,  # WSAHOST_NOT_FOUND
}


RESOLVED = "resolved"
NXDOMAIN = "nxdomain"
UNKNOWN = "unknown"

# Keyed by hostname, so --ip reuses the lookup host selection already did.
_LOOKUP_CACHE = {}


def lookup(host):
    """Resolve a name once. Returns (addresses, state)."""
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
    """Forget every resolution. The cache never expires on its own."""
    _LOOKUP_CACHE.clear()


def addresses(host):
    """Every address a name points at, or [] if it does not resolve."""
    return lookup(host)[0]


def resolves(host):
    """Whether DNS has an address record for this name."""
    name = hostname_of(host)
    if not name:
        return False
    return lookup(name)[1] != NXDOMAIN


def short_error(error):
    """Condense a nested requests/urllib3 error to one printable phrase."""
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
    """GET a hostname over HTTPS, falling back to HTTP."""
    last_error = ""
    for scheme in ("https", "http"):
        url = "%s://%s" % (scheme, host)
        response, error = session.get(url, **kw)
        if response is not None:
            return url, response, ""
        last_error = error
    return "https://%s" % host, None, last_error
