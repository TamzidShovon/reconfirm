"""Publicly listable cloud storage under names derived from the target.

Bucket namespaces are global and flat, so a listable bucket matching a
guessed name is not necessarily the target's. Ownership is evidenced by the
file keys inside: keys referencing the target confirm it, foreign keys
disprove it, and an empty bucket proves neither and stays unverified.
"""

NAME = "buckets"
DESCRIPTION = "publicly listable cloud storage owned by the target"

import re

from ..confidence import confirmed, inconclusive, unverified, discarded

# Labels that describe a function, not an owner. A candidate derived from
# one of these usually belongs to an unrelated company.
GENERIC_LABELS = {
    "sandbox", "app", "apps", "api", "dev", "www", "test", "staging", "stage",
    "prod", "production", "beta", "demo", "portal", "static", "assets", "cdn",
    "dashboard", "admin", "files", "data", "vault", "my", "shop", "store",
    "secure", "mail", "smtp", "blog", "docs", "status", "help", "support",
    "account", "accounts", "login", "auth", "sso", "web", "mobile", "internal",
    "external", "public", "private", "media", "img", "images", "video", "edge",
}

SUFFIXES = [
    "", "-assets", "-static", "-uploads", "-backups", "-backup", "-data",
    "-dev", "-staging", "-prod", "-media", "-files", "-images", "-public",
    "-private", "-logs", "-archive",
]

PROVIDERS = [
    ("AWS S3", "https://{name}.s3.amazonaws.com"),
    ("AWS S3", "https://s3.amazonaws.com/{name}"),
    ("Google Cloud Storage", "https://storage.googleapis.com/{name}"),
]

# Markers that a response is a directory listing rather than an error page.
LISTING_MARKERS = ("<ListBucketResult", "<Contents>")

KEY_PATTERN = re.compile(r"<Key>([^<]+)</Key>")

# Enough keys to show ownership and give the reader a sense of the contents.
EVIDENCE_KEYS = 15


# Registry labels sitting directly under a ccTLD, so `acme.co.uk` reads as
# one registrable domain. A heuristic, not the Public Suffix List.
SECOND_LEVEL_REGISTRIES = {"co", "com", "net", "org", "edu", "gov", "ac", "or", "ne", "gob"}


def _registrable_labels(domain):
    """The domain's labels with its public suffix removed."""
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_REGISTRIES:
        return labels[:-2], labels[-2:]
    return labels[:-1], labels[-1:]


def organisation_name(domain):
    """The most owner-like label in a domain.

    `cdn.district.in` -> `district`. Falls back to the first label when every
    label is generic.
    """
    labels, _suffix = _registrable_labels(domain)
    meaningful = [l for l in labels if l not in GENERIC_LABELS]
    if meaningful:
        return meaningful[-1]
    return (labels or domain.split("."))[0]


def root_domain(domain):
    labels, suffix = _registrable_labels(domain)
    if not labels:
        return domain.rstrip(".").lower()
    return ".".join([labels[-1]] + suffix)


def candidates(domain):
    name = organisation_name(domain)
    return [name + suffix for suffix in SUFFIXES]


def _ownership(keys, domain):
    """Decide whether file keys evidence the target's ownership.

    Returns (state, reason).
    """
    if not keys:
        return "empty", (
            "the bucket is listable but empty, so nothing evidences who owns it - "
            "confirm by hand before treating it as the target's"
        )
    haystack = " ".join(keys).lower()
    name = organisation_name(domain)
    root = root_domain(domain)
    if root.lower() in haystack or name in haystack:
        return "owned", ""
    return "foreign", (
        "the bucket is listable but its file keys reference neither %r nor %r - "
        "it belongs to an unrelated party and is not this target's exposure"
        % (root, name)
    )


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []
    domain = target.domain
    probed = 0

    for name in candidates(domain):
        for provider, template in PROVIDERS:
            url = template.format(name=name)

            # Storage endpoints belong to the provider, not the target.
            response, error = session.get_external(url, timeout=6)
            probed += 1
            if response is None:
                results.append(
                    inconclusive(NAME, url, "%s bucket %r not checked" % (provider, name), error)
                )
                continue

            if response.status_code == 403:
                results.append(
                    unverified(
                        NAME, url,
                        "%s bucket %r exists but denies listing" % (provider, name),
                        "a private bucket is not an exposure; noted because it confirms "
                        "the naming convention for manual follow-up",
                    )
                )
                continue

            if response.status_code != 200:
                continue
            if not any(marker in response.text for marker in LISTING_MARKERS):
                continue

            keys = KEY_PATTERN.findall(response.text)
            state, reason = _ownership(keys, domain)

            if state == "owned":
                emit("  %s %s is listable and owned" % (provider, name))
                results.append(
                    confirmed(
                        NAME, url,
                        "publicly listable %s bucket holding the target's files" % provider,
                        evidence="\n".join(keys[:EVIDENCE_KEYS]),
                    )
                )
            elif state == "empty":
                results.append(
                    unverified(
                        NAME, url,
                        "publicly listable %s bucket %r, ownership unproven" % (provider, name),
                        reason,
                    )
                )
            else:
                results.append(
                    discarded(
                        NAME, url,
                        "publicly listable %s bucket %r belongs to someone else"
                        % (provider, name),
                        reason,
                    )
                )

    if not results and probed:
        # This check guesses at names, so "found nothing" is a statement
        # about the names guessed, not about the target's storage.
        results.append(
            discarded(
                NAME, domain,
                "no listable bucket under %d guessed names" % probed,
                "names were derived from %r across %d providers; none returned a "
                "public listing, which says nothing about buckets under names this "
                "check does not guess"
                % (organisation_name(domain), len(PROVIDERS)),
            )
        )

    return results
