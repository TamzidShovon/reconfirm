"""
Publicly listable cloud storage under names derived from the target.

The technique is guessing: take the organisation name, append the handful of
suffixes everyone uses, and see which buckets answer. It works often enough to
be worth doing and produces a specific, recurring false positive that most
tools ship with.

That false positive is ownership. Bucket namespaces are global and flat, so
`dashboard`, `files` and `data` were claimed years ago by parties with no
relation to the target. A tool that derives a candidate, finds it listable and
reports it has proven only that *a* bucket by that name exists and is open —
not that it belongs to the organisation being assessed. Reporting someone
else's open bucket to a bug bounty programme is worse than reporting nothing.

So ownership has to be evidenced, and the only evidence available is the file
keys inside. If the listing contains keys referencing the target's domain or
name, the bucket is theirs and the finding is CONFIRMED. If the listing is
empty, nothing has been shown either way and it stays UNVERIFIED — an empty
bucket is not disproof, and this is exactly the case where the asymmetry in
confidence.py earns its keep. If the keys reference somebody else, ownership
is positively disproven and the candidate is DISCARDED.

Derivation matters for the same reason. Taking the first label of
`dashboard.example.com` yields the candidate `dashboard`, which is why the
generic-label list below exists: those labels describe a function, not an
owner, and every one of them is a bucket somebody already owns.
"""

NAME = "buckets"
DESCRIPTION = "publicly listable cloud storage owned by the target"

import re

from ..confidence import confirmed, inconclusive, unverified, discarded

# Subdomain labels that say nothing about who owns a domain. Deriving a
# candidate from one of these produces a bucket name belonging to an unrelated
# company far more often than not.
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


# Registry labels that sit directly under a ccTLD, so that `acme.co.uk` is
# read as one registrable domain rather than as a subdomain of `co.uk`. This
# is a heuristic, not the Public Suffix List: the full list is a dependency
# and a data file to keep current, and getting `co.uk` and `com.au` right
# covers what this check actually needs. A miss costs a slightly wrong bucket
# candidate, which the ownership rule then discards.
SECOND_LEVEL_REGISTRIES = {"co", "com", "net", "org", "edu", "gov", "ac", "or", "ne", "gob"}


def _registrable_labels(domain):
    """The domain's labels with its public suffix removed."""
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_REGISTRIES:
        return labels[:-2], labels[-2:]
    return labels[:-1], labels[-1:]


def organisation_name(domain):
    """The most owner-like label in a domain.

    `cdn.district.in` -> `district`, not `cdn`. Falls back to the first label
    when every label is generic, because a wrong guess that gets DISCARDED on
    ownership is better than silently checking nothing.
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

    Returns (state, reason). Splitting this out keeps the rule readable and
    lets the tests assert it directly without any HTTP.
    """
    if not keys:
        return "empty", (
            "the bucket is listable but empty, so nothing evidences who owns it — "
            "confirm by hand before treating it as the target's"
        )
    haystack = " ".join(keys).lower()
    name = organisation_name(domain)
    root = root_domain(domain)
    if root.lower() in haystack or name in haystack:
        return "owned", ""
    return "foreign", (
        "the bucket is listable but its file keys reference neither %r nor %r — "
        "it belongs to an unrelated party and is not this target's exposure"
        % (root, name)
    )


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []
    domain = target.domain

    for name in candidates(domain):
        for provider, template in PROVIDERS:
            url = template.format(name=name)

            # Storage endpoints belong to the cloud provider, not the target,
            # so they are fetched outside the scope rail by design.
            response, error = session.get_external(url, timeout=6)
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

    return results
