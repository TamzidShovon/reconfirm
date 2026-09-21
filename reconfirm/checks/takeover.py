"""
Dangling-hostname detection.

A subdomain pointed by CNAME at a service that no longer hosts anything can
often be claimed by whoever registers that name on the service next. The
service itself announces this: it serves a distinctive page saying it has no
instance by that name.

What this check can and cannot establish is worth being precise about, because
the distinction is exactly where other tools overclaim. Reading that page
proves the *service* reports no instance. It does not prove the name is still
available to register, and it does not prove the DNS record is dangling rather
than simply misconfigured. So a fingerprint match is CONFIRMED for the claim
this check actually makes — "this host serves <service>'s unclaimed-instance
page" — and the summary says that, rather than "subdomain takeover", which is a
conclusion the operator reaches after checking whether the name can be claimed.
"""

NAME = "takeover"
DESCRIPTION = "hosts serving a provider's unclaimed-instance page"

from ..confidence import confirmed, discarded, inconclusive, unverified
from ..net import BudgetExhausted, OutOfScope, fetch_site, resolves, short_error

# Each entry is (marker, service). Markers are the literal text these services
# serve for a name they do not host. They are matched case-insensitively
# against the start of the body only — see _BODY_WINDOW.
FINGERPRINTS = [
    ("There isn't a GitHub Pages site here", "GitHub Pages"),
    ("No such app", "Heroku"),
    ("NoSuchBucket", "AWS S3"),
    ("The specified bucket does not exist", "AWS S3"),
    ("Sorry, this shop is currently unavailable", "Shopify"),
    ("Fastly error: unknown domain", "Fastly"),
    ("404 error unknown site!", "Pantheon"),
    ("Do you want to register", "WordPress.com"),
    ("Ghost cannot find a matching Ghost", "Ghost"),
    ("Help Center Closed", "Zendesk"),
    ("There is no helpdesk here", "Freshdesk"),
    ("The feed has not been found", "Feedburner"),
    ("This UserVoice subdomain is currently available", "UserVoice"),
    ("project not found", "Surge.sh"),
    ("Repository not found", "Bitbucket"),
]

# Markers are matched inside this many bytes of the response. An unclaimed-
# instance page is small and says so immediately; a phrase like "No such app"
# appearing 400KB into a bundled application script is a coincidence, and
# matching the whole body is how that coincidence becomes a reported finding.
_BODY_WINDOW = 4000


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []

    for host in target.hosts:
        if not resolves(host):
            # No DNS record at all, so there is no dangling CNAME and nothing
            # to claim. Definitive, unlike the failures handled below.
            results.append(
                discarded(
                    NAME, host, "name does not resolve",
                    "DNS has no address record for this name, so nothing is pointed "
                    "anywhere and there is no host to test",
                )
            )
            continue

        try:
            url, response, error = fetch_site(session, host, allow_redirects=True)
        except OutOfScope as e:
            results.append(unverified(NAME, host, "not probed", str(e)))
            continue
        except BudgetExhausted as e:
            results.append(inconclusive(NAME, host, "not probed", e))
            break

        if response is None:
            # An unresolvable or unreachable host is the single most common
            # outcome of enumerating a CT log, and it is genuinely ambiguous:
            # a dead A record and a dangling CNAME to a dead provider look
            # identical from here. It stays unverified.
            # The name resolves but nothing answered. Genuinely ambiguous: a
            # firewalled host and a dead one look identical from here.
            results.append(
                unverified(
                    NAME, host, "host did not respond",
                    "the name resolves but neither HTTPS nor HTTP answered - %s"
                    % short_error(error),
                )
            )
            continue

        body = response.text[:_BODY_WINDOW]
        lowered = body.lower()
        matched = False

        for marker, service in FINGERPRINTS:
            index = lowered.find(marker.lower())
            if index == -1:
                continue

            matched = True
            if session.is_catchall_response(url, response):
                results.append(
                    discarded(
                        NAME, url,
                        "%s marker present but response is the host's catch-all" % service,
                        "body matches this origin's answer to a nonexistent path, so the "
                        "marker is part of a page served for every request",
                    )
                )
                break

            snippet = body[max(0, index - 80): index + len(marker) + 160]
            results.append(
                confirmed(
                    NAME, url,
                    "serves %s's unclaimed-instance page - check whether the name can "
                    "still be registered" % service,
                    evidence=snippet.strip(),
                )
            )
            emit("  %s -> %s" % (host, service))
            break

        if not matched:
            # A host that answered and matched no provider marker was checked
            # and is clean. Omitting it would make "checked, nothing found"
            # indistinguishable from "never checked", which is the confusion
            # this whole package is built to prevent.
            results.append(
                discarded(
                    NAME, url,
                    "responded, no provider unclaimed-instance marker",
                    "all %d provider fingerprints were tested against the first "
                    "%d bytes of the response and none matched"
                    % (len(FINGERPRINTS), _BODY_WINDOW),
                )
            )

    return results
