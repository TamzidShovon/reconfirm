"""Credential material in served JavaScript.

Structural patterns identify a credential by a format nothing else uses, so
the match is the evidence. Contextual patterns identify an assignment that
might hold one, and the captured value must clear a placeholder list and an
entropy floor before it is claimed.

Values are redacted before they reach a report.
"""

NAME = "secrets"
DESCRIPTION = "credential material in served JavaScript"

import math
import re
from urllib.parse import urljoin

from ..confidence import confirmed, discarded, inconclusive, unverified
from ..net import BudgetExhausted, OutOfScope, fetch_site, resolves, short_error

# Self-evidencing formats: the match is the finding.
STRUCTURAL_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20}"), "GitLab personal access token"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "Stripe live secret key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]{10,}"), "MongoDB connection string"),
    (
        re.compile(
            r"(?:postgres|postgresql|mysql|redis)://[^\s\"'<>/]+:[^\s\"'<>/]+@[^\s\"'<>]{4,}"
        ),
        "database URL with inline credentials",
    ),
]

# Patterns whose captured group still has to survive validation.
CONTEXTUAL_PATTERNS = [
    (
        re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[\"']([^\"']{8,})[\"']"),
        "API key",
    ),
    (
        re.compile(
            r"(?i)(?:client_secret|app_secret|secret[_-]?key)\s*[:=]\s*[\"']([^\"']{8,})[\"']"
        ),
        "secret key",
    ),
    (
        re.compile(
            r"(?i)(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"']([^\"']{12,})[\"']"
        ),
        "access token",
    ),
    (
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{6,})[\"']"),
        "password",
    ),
]

# Structural in shape but routinely non-secret in content, so surfaced
# without being claimed as proven.
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)

# A bare PEM header matches key-handling code too, so base64 key material
# must follow it.
PEM_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"[\r\n\s]+([A-Za-z0-9+/=\r\n\s]{100,})"
)

PLACEHOLDERS = {
    "", "null", "none", "nil", "undefined", "todo", "tbd", "xxx", "xxxx",
    "changeme", "change_me", "placeholder", "example", "test", "testing",
    "secret", "password", "passwd", "your_api_key", "your_api_key_here",
    "your-api-key-here", "api_key", "apikey", "token", "dummy", "sample",
    "fake", "redacted", "hidden", "value", "string", "foo", "bar",
}

# Shannon entropy per character: hex ~4.0, base64 ~5.0, short English
# identifiers well under 3.0.
MIN_ENTROPY = 3.0
MIN_LENGTH = 12

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
INLINE_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)

MAX_SCRIPTS_PER_HOST = 12


def shannon_entropy(value):
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in (value.count(c) for c in set(value))
    )


def redact(value):
    """Keep enough to locate the string in the bundle, not enough to use it."""
    if len(value) <= 10:
        return value[:2] + "*" * (len(value) - 2)
    return "%s%s%s" % (value[:4], "*" * min(12, len(value) - 8), value[-4:])


def classify_value(value):
    """Decide whether a captured value can support a claim.

    Returns (ok, reason); the reason becomes the DISCARDED reason verbatim.
    """
    value = (value or "").strip()
    if not value:
        return False, "the matched assignment has an empty value"
    if value.lower() in PLACEHOLDERS:
        return False, "the value %r is a known placeholder, not a credential" % value
    if len(value) < MIN_LENGTH:
        return False, (
            "the value is %d characters - too short to be a credential" % len(value)
        )
    if value.startswith(("/", "./", "../", "http://", "https://")):
        return False, "the value is a URL or path, not a credential"
    if " " in value and re.fullmatch(r"[\w\s\-]*", value):
        return False, "the value is a phrase, not a credential"
    entropy = shannon_entropy(value)
    if entropy < MIN_ENTROPY:
        return False, (
            "the value carries %.2f bits of entropy per character, below the %.1f "
            "floor - it reads as a word or identifier rather than random material"
            % (entropy, MIN_ENTROPY)
        )
    return True, ""


def _collect_sources(session, host):
    """Return ([(url, content)], error) for the page and the scripts it loads."""
    origin, response, error = fetch_site(session, host, allow_redirects=True)
    if response is None:
        return [], error

    sources = []
    inline = "\n".join(INLINE_SCRIPT.findall(response.text))
    if inline.strip():
        sources.append(("%s (inline)" % origin, inline))

    for src in SCRIPT_SRC.findall(response.text)[:MAX_SCRIPTS_PER_HOST]:
        url = src if src.startswith("http") else urljoin(origin, src)
        try:
            script, _error = session.get(url)
        except OutOfScope:
            # Out of scope by design: a key in a third-party CDN bundle is
            # not this target's finding.
            continue
        if script is not None:
            sources.append((url, script.text))
    return sources, ""


def _scan(source_url, content):
    results = []
    seen = set()

    for pattern, label in STRUCTURAL_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(0)
            if value in seen:
                continue
            seen.add(value)
            results.append(
                confirmed(
                    NAME,
                    source_url,
                    "%s present in served script" % label,
                    evidence="%s: %s" % (label, redact(value)),
                )
            )

    for pattern, label in CONTEXTUAL_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1)
            if value in seen:
                continue
            seen.add(value)
            ok, reason = classify_value(value)
            if ok:
                results.append(
                    confirmed(
                        NAME,
                        source_url,
                        "%s assigned a high-entropy literal in served script" % label,
                        evidence="%s = %s (%.2f bits/char)"
                        % (label, redact(value), shannon_entropy(value)),
                    )
                )
            else:
                results.append(
                    discarded(
                        NAME,
                        source_url,
                        "%s assignment matched but rejected" % label,
                        reason,
                    )
                )

    for match in PEM_PATTERN.finditer(content):
        body = re.sub(r"\s+", "", match.group(1))
        if len(body) < 100:
            continue
        results.append(
            confirmed(
                NAME,
                source_url,
                "PEM private key block with base64 key material",
                evidence="-----BEGIN PRIVATE KEY----- followed by %d bytes of base64"
                % len(body),
            )
        )

    for match in JWT_PATTERN.finditer(content):
        value = match.group(0)
        if value in seen:
            continue
        seen.add(value)
        results.append(
            unverified(
                NAME,
                source_url,
                "JWT present in served script",
                "a JWT in client-side code is frequently a public demo or an expired "
                "fixture token - decode the payload and check its claims and expiry",
            )
        )

    return results


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []

    for host in target.hosts:
        if not resolves(host):
            results.append(
                discarded(
                    NAME, host, "name does not resolve",
                    "DNS has no address record for this name, so there is nothing "
                    "serving scripts to scan",
                )
            )
            continue

        try:
            sources, error = _collect_sources(session, host)
        except OutOfScope as e:
            results.append(unverified(NAME, host, "not scanned", str(e)))
            continue
        except BudgetExhausted as e:
            results.append(inconclusive(NAME, host, "not scanned", e))
            break

        if not sources:
            results.append(
                unverified(
                    NAME,
                    host,
                    "no scripts retrieved",
                    short_error(error) if error
                    else "the page served no inline or linked scripts",
                )
            )
            continue

        found = []
        for source_url, content in sources:
            hits = _scan(source_url, content)
            if hits:
                emit("  %s: %d match(es)" % (source_url, len(hits)))
            found.extend(hits)

        if not found:
            # Reported rather than omitted, so scanned-clean is
            # distinguishable from never-checked.
            results.append(
                discarded(
                    NAME, host,
                    "scanned %d script source(s), no credential material" % len(sources),
                    "every pattern was tested against the retrieved scripts and "
                    "nothing matched",
                )
            )
        results.extend(found)

    return results
