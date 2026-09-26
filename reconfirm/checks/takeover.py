"""Dangling-hostname detection.

A fingerprint match confirms only that the host serves a provider's
unclaimed-instance page. Whether the name can still be registered is a
separate manual step, and the summary says so.
"""

NAME = "takeover"
DESCRIPTION = "hosts serving a provider's unclaimed-instance page"

from ..confidence import confirmed, discarded, inconclusive, unverified
from ..net import BudgetExhausted, OutOfScope, fetch_site, resolves, short_error

# (marker, service). Matched case-insensitively within _BODY_WINDOW.
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

# An unclaimed-instance page says so immediately. "No such app" appearing
# deep in a bundled script is a coincidence, not a provider error page.
_BODY_WINDOW = 4000


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []

    for host in target.hosts:
        if not resolves(host):
            # No DNS record, so nothing is pointed anywhere. Definitive.
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
            # Per-host, not per-run: Session tracks the budget separately for
            # each hostname, so host B still has its full budget even though
            # host A just spent its own.
            results.append(inconclusive(NAME, host, "not probed", e))
            continue

        if response is None:
            # Resolves but nothing answered: a firewalled host and a dead
            # one look identical from here.
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
            try:
                is_catchall = session.is_catchall_response(url, response)
            except BudgetExhausted as e:
                # The catch-all probe is itself a request, and the marker
                # match and a spent budget can land on the same host at the
                # same time. A real unclaimed-instance page and a catch-all
                # serving the same text are indistinguishable without it -
                # report what was seen, not a guess at which one this is.
                results.append(
                    inconclusive(
                        NAME, url,
                        "%s marker present, could not rule out a catch-all" % service,
                        e,
                    )
                )
                break
            if is_catchall:
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
            # Reported rather than omitted, so "checked, nothing found" is
            # distinguishable from "never checked".
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
