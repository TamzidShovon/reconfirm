"""
Credential material in served JavaScript.

Regex secret scanning is the noisiest technique in recon. Run a pattern like
`apiKey = "..."` over a bundled application and it matches the library that
*reads* API keys, the config template shipping with placeholders, the test
fixture, and the masked-display component — all before it matches anything
real. A scanner that reports every match is describing the shape of the code,
not finding a secret.

Three rules cut that down, and they are the substance of this check:

1. Patterns come in two kinds. A *structural* pattern (AKIA..., ghp_...,
   sk_live_...) identifies a credential by a format nothing else uses, so the
   match is itself the evidence. A *contextual* pattern (`secret: "..."`) only
   identifies an assignment that might hold one, and the captured value still
   has to earn the claim. Conflating the two is why generic scanners
   over-report.

2. The captured value is judged, not the surrounding text. `apiKey = ""`
   matched as a whole string looks like a twelve-character secret; the value
   is empty.

3. Contextual matches must clear both a placeholder list and an entropy floor.
   Real credentials are drawn from a large random space and look it;
   "changeme", "your_api_key_here" and "/api/v1/users" do not.

Values are redacted before they reach a report. A tool whose output file is
itself a list of live credentials has made the problem worse, and the first
and last few characters are enough to locate the string in the bundle.
"""

NAME = "secrets"
DESCRIPTION = "credential material in served JavaScript"

import math
import re
from urllib.parse import urljoin

from ..confidence import confirmed, discarded, inconclusive, unverified
from ..net import BudgetExhausted, OutOfScope, fetch_site

# Self-evidencing formats. The match is the finding: nothing else looks like
# this, so there is nothing further to validate.
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

# A JWT is structural in shape but routinely non-secret in content — public
# demo tokens and expired fixtures are everywhere — so it is surfaced without
# being claimed as proven.
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)

# A bare PEM header matches key-handling code and masked-display components as
# readily as it matches a key. Requiring base64 body after it is the whole
# difference; see docs/CONFIDENCE.md.
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

# Shannon entropy per character. Hex sits near 4.0, base64 near 5.0, and short
# English identifiers well under 3.0. The floor admits short real keys while
# rejecting words and paths.
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

    Returns (ok, reason). The reason becomes the DISCARDED reason verbatim, so
    it explains the rejection rather than just naming it.
    """
    value = (value or "").strip()
    if not value:
        return False, "the matched assignment has an empty value"
    if value.lower() in PLACEHOLDERS:
        return False, "the value %r is a known placeholder, not a credential" % value
    if len(value) < MIN_LENGTH:
        return False, (
            "the value is %d characters — too short to be a credential" % len(value)
        )
    if value.startswith(("/", "./", "../", "http://", "https://")):
        return False, "the value is a URL or path, not a credential"
    if " " in value and re.fullmatch(r"[\w\s\-]*", value):
        return False, "the value is a phrase, not a credential"
    entropy = shannon_entropy(value)
    if entropy < MIN_ENTROPY:
        return False, (
            "the value carries %.2f bits of entropy per character, below the %.1f "
            "floor — it reads as a word or identifier rather than random material"
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
            # Third-party CDN scripts fall outside scope by design: a key in
            # Google's analytics bundle is not this target's finding.
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
                "fixture token — decode the payload and check its claims and expiry",
            )
        )

    return results


def run(session, target, emit=None):
    emit = emit or (lambda _msg: None)
    results = []

    for host in target.hosts:
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
                    error or "the page served no inline or linked scripts",
                )
            )
            continue

        for source_url, content in sources:
            found = _scan(source_url, content)
            if found:
                emit("  %s: %d match(es)" % (source_url, len(found)))
            results.extend(found)

    return results
