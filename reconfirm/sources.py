"""Passive sources of candidate hostnames.

Nothing here touches the target: certificate transparency and the Wayback
Machine are third-party archives. Sources return candidates, never results;
deciding what is actually there is the checks' job.
"""

import json
import re
from urllib.parse import urlparse

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
WAYBACK_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
)

# A CT log entry for a wildcard cert yields "*.example.com", which is not a
# host you can connect to. Labels that are purely structural get dropped.
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def _clean(name, domain):
    name = (name or "").strip().lower().rstrip(".")
    name = name.lstrip("*.")
    if not name or name == domain:
        return None
    if not name.endswith("." + domain):
        return None
    if not _HOSTNAME_RE.match(name):
        return None
    # A name containing the domain twice is a concatenation artifact
    # ("testasp.vulnweb.comtestasp.vulnweb.com"), never a real host.
    if name.count(domain) > 1:
        return None
    # Percent-escape artifacts ("2ftestphp" from %2f) are deliberately not
    # filtered here: the obvious rule also rejects 2fa and 3d, which are
    # ordinary subdomains. The caller resolves every name before probing,
    # and DNS is evidence rather than a heuristic.
    return name


def from_certificates(session, domain, limit=500):
    """Subdomains from certificate transparency, via crt.sh."""
    r, err = session.get_external(CRTSH_URL.format(domain=domain), timeout=30)
    if r is None:
        return [], "crt.sh unreachable (%s)" % err
    if r.status_code != 200:
        return [], "crt.sh returned HTTP %d" % r.status_code

    try:
        entries = r.json()
    except (ValueError, json.JSONDecodeError):
        # crt.sh serves an HTML error page under load rather than a JSON error.
        return [], "crt.sh returned a non-JSON body (it is likely rate-limiting)"

    found = set()
    for entry in entries:
        # One entry can carry several SANs, newline-separated.
        for raw in (entry.get("name_value") or "").split("\n"):
            name = _clean(raw, domain)
            if name:
                found.add(name)
    return sorted(found)[:limit], ""


def from_wayback(session, domain, limit=2000):
    """Subdomains seen in archived URLs."""
    r, err = session.get_external(
        WAYBACK_URL.format(domain=domain, limit=limit), timeout=30
    )
    if r is None:
        return [], "web.archive.org unreachable (%s)" % err
    if r.status_code != 200:
        return [], "web.archive.org returned HTTP %d" % r.status_code

    found = set()
    for line in r.text.splitlines():
        host = urlparse(line.strip()).hostname
        name = _clean(host, domain)
        if name:
            found.add(name)
    return sorted(found), ""


def enumerate_hosts(session, domain, use_wayback=True, emit=None):
    """Run every enabled source and merge the candidates."""
    emit = emit or (lambda _msg: None)
    # The apex is given, not discovered. Seeding it means a source outage
    # degrades to "checked the apex only" rather than checking nothing.
    candidates = {domain.lower().strip().rstrip(".")}
    notes = []

    emit("querying certificate transparency")
    hosts, note = from_certificates(session, domain)
    candidates.update(hosts)
    if note:
        notes.append(note)
    emit("  %d hostnames from crt.sh" % len(hosts))

    if use_wayback:
        emit("querying the wayback machine")
        hosts, note = from_wayback(session, domain)
        candidates.update(hosts)
        if note:
            notes.append(note)
        emit("  %d hostnames from web.archive.org" % len(hosts))

    return sorted(candidates), notes
