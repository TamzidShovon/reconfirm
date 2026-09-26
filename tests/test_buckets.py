"""Name derivation and the ownership rule."""

import pytest

from reconfirm.checks import buckets


@pytest.mark.parametrize("domain, expected", [
    ("example.com", "example"),
    ("cdn.district.in", "district"),
    ("dashboard.acme.co.uk", "acme"),
    ("api.staging.contoso.com", "contoso"),
    ("www.example.com", "example"),
])
def test_organisation_name_skips_generic_labels(domain, expected):
    assert buckets.organisation_name(domain) == expected


def test_generic_only_domain_falls_back_rather_than_skipping():
    # Every label is generic. Guessing and being discarded on ownership beats
    # silently checking nothing.
    assert buckets.organisation_name("api.cdn.dev") == "api"


def test_candidates_include_the_bare_name():
    names = buckets.candidates("example.com")
    assert "example" in names
    assert "example-backups" in names


def test_keys_referencing_the_target_prove_ownership():
    state, reason = buckets._ownership(
        ["uploads/example.com/logo.png", "invoices/2026.pdf"], "example.com"
    )
    assert state == "owned"
    assert reason == ""


def test_keys_matching_the_org_name_prove_ownership():
    state, _ = buckets._ownership(["example-prod-db-dump.sql"], "example.com")
    assert state == "owned"


def test_empty_bucket_is_unproven_not_disproven():
    # An empty listing is not evidence the bucket belongs to someone else.
    state, reason = buckets._ownership([], "example.com")
    assert state == "empty"
    assert "nothing evidences who owns it" in reason


def test_foreign_keys_disprove_ownership():
    state, reason = buckets._ownership(
        ["customers/northwind/report.csv", "northwind-logo.svg"], "example.com"
    )
    assert state == "foreign"
    assert "unrelated party" in reason


def test_ownership_match_is_case_insensitive():
    state, _ = buckets._ownership(["Uploads/EXAMPLE.COM/x.png"], "example.com")
    assert state == "owned"


def test_short_org_name_is_not_fooled_by_an_unrelated_word_containing_it():
    # candidates() guesses short names from short domains ("go.dev" -> "go"),
    # and a plain substring check then matches "go" inside "logo" - an
    # ordinary word in a totally unrelated bucket, not evidence of anything.
    state, reason = buckets._ownership(
        ["logo.png", "company-logo-2023.svg", "banner.jpg"], "go.dev"
    )
    assert state == "foreign"
    assert "unrelated party" in reason


def test_org_name_as_its_own_token_still_proves_ownership():
    # The word-boundary fix must not stop matching the legitimate case: the
    # name appearing as its own token, just hyphenated rather than bare.
    state, _ = buckets._ownership(["backup-go-2024.tar.gz"], "go.dev")
    assert state == "owned"


# --- IP-literal targets ---

@pytest.mark.parametrize("target", [
    "127.0.0.1", "10.0.0.1", "192.168.1.50", "8.8.8.8", "::1",
    "2606:2800:220:1:248:1893:25c8:1946",
])
def test_ip_literals_are_recognised(target):
    assert buckets.is_ip_literal(target)


@pytest.mark.parametrize("target", [
    "example.com", "cdn.district.in", "acme.co.uk", "", "1.2.3.4.example.com",
])
def test_domains_are_not_ip_literals(target):
    assert not buckets.is_ip_literal(target)


def test_ip_target_declines_instead_of_guessing_names():
    # 127.0.0.1 used to derive the organisation name "0" and then probe real
    # buckets named 0-media, 0-public and so on, which belong to strangers.
    from reconfirm.checks import Target
    from reconfirm.confidence import DISCARDED

    class NoNetwork:
        def get_external(self, *a, **kw):
            raise AssertionError("an IP target must not reach any storage endpoint")

    results = buckets.run(NoNetwork(), Target(domain="127.0.0.1", hosts=["127.0.0.1"]))
    assert [r.state for r in results] == [DISCARDED]
    assert "IP address" in results[0].summary
