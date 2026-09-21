"""
The value-classification rules, and the scan built on them.

Each rejection case below is a false positive that a plain regex scanner
reports as a finding.
"""

import pytest

from reconfirm.checks import Target, secrets
from reconfirm.confidence import CONFIRMED, DISCARDED, UNVERIFIED
from tests.conftest import Routes


# ── value classification ──────────────────────────────────────────────────

@pytest.mark.parametrize("value, fragment", [
    ("", "empty value"),
    ("changeme", "placeholder"),
    ("your_api_key_here", "placeholder"),
    ("abc123", "too short"),
    ("/api/v1/users/profile", "URL or path"),
    ("https://example.com/callback", "URL or path"),
    ("the quick brown fox jumps", "phrase"),
    ("aaaaaaaaaaaaaaaaaaaaaa", "entropy"),
])
def test_rejected_values(value, fragment):
    ok, reason = secrets.classify_value(value)
    assert not ok
    assert fragment in reason


# Synthetic values, not real vendor test keys. A published example key still
# matches its vendor's format, so committing one trips secret-scanning push
# protection and teaches anyone reading the suite that checking in
# credential-shaped strings is fine. These carry the same length and entropy
# without matching any issuer's pattern.
@pytest.mark.parametrize("value", [
    "Kp7mQ2xR9vT4wZ8nB3cF6hJ1",
    "f4c3b2a1908d7e6f5a4b3c2d1e0f9a8b",
    "xJ9k2LmQ7pR4sT6vW8yZ1aB3cD5eF7gH",
    "7Ld0Nq5Yw2Hs8Vb4Gm1Rz6Tj3Xc9Pk",
])
def test_accepted_values(value):
    ok, reason = secrets.classify_value(value)
    assert ok, reason


def test_entropy_separates_random_from_english():
    assert secrets.shannon_entropy("xJ9k2LmQ7pR4sT6vW8yZ") > secrets.MIN_ENTROPY
    assert secrets.shannon_entropy("passwordpassword") < secrets.MIN_ENTROPY


def test_redaction_keeps_locator_not_credential():
    redacted = secrets.redact("AKIAIOSFODNN7EXAMPLE")
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert "IOSFODNN" not in redacted


# ── scanning ──────────────────────────────────────────────────────────────

def test_structural_match_is_confirmed():
    results = secrets._scan("x.js", 'const k = "AKIAIOSFODNN7EXAMPLE";')
    assert [r.state for r in results] == [CONFIRMED]
    assert "AWS access key id" in results[0].summary


def test_placeholder_assignment_is_discarded_with_the_reason():
    results = secrets._scan("x.js", 'apiKey: "your_api_key_here"')
    assert [r.state for r in results] == [DISCARDED]
    assert "placeholder" in results[0].reason


def test_empty_assignment_is_discarded_not_reported_as_a_secret():
    # The bug this rule exists for: matching the whole assignment text and
    # reporting it as though the text were the secret.
    results = secrets._scan("x.js", 'const rss2jsonApiKey = "";')
    assert all(r.state == DISCARDED for r in results)


def test_bare_pem_header_is_not_confirmed():
    # A header with no key material behind it is what key-handling code and
    # masked-display components contain.
    content = 'const PREFIX = "-----BEGIN PRIVATE KEY-----";'
    assert secrets._scan("x.js", content) == []


def test_pem_with_key_material_is_confirmed():
    content = "-----BEGIN PRIVATE KEY-----\n" + ("MIIEvQIBADANBg" * 12) + "\n"
    results = secrets._scan("x.js", content)
    assert [r.state for r in results] == [CONFIRMED]


def test_jwt_is_surfaced_but_not_claimed():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    results = secrets._scan("x.js", 'const t = "%s";' % token)
    states = {r.state for r in results}
    assert CONFIRMED not in states
    assert UNVERIFIED in states


def test_duplicate_matches_reported_once():
    key = "AKIAIOSFODNN7EXAMPLE"
    results = secrets._scan("x.js", "a=%s; b=%s; c=%s" % (key, key, key))
    assert len(results) == 1


# ── end to end against a server ───────────────────────────────────────────

def test_run_fetches_linked_scripts(server, session):
    routes = Routes()
    routes.add("/", '<html><script src="/app.js"></script></html>')
    routes.add("/app.js", 'var k="AKIAIOSFODNN7EXAMPLE";', ctype="application/javascript")
    origin = server(routes)

    target = Target(domain="127.0.0.1", hosts=[origin.split("//")[1]])
    results = secrets.run(session, target)

    confirmed = [r for r in results if r.state == CONFIRMED]
    assert len(confirmed) == 1
    assert "app.js" in confirmed[0].target


def test_run_reports_no_scripts_as_unverified(server, session):
    routes = Routes().add("/", "<html><body>nothing here</body></html>")
    origin = server(routes)

    target = Target(domain="127.0.0.1", hosts=[origin.split("//")[1]])
    results = secrets.run(session, target)

    assert [r.state for r in results] == [UNVERIFIED]
    assert "no scripts" in results[0].summary
