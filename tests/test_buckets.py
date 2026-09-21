"""
Name derivation and the ownership rule.

The ownership rule is the reason this check exists in the form it does, so it
is tested as a pure function rather than only through HTTP — the rule should be
readable and assertable without a network in the picture.
"""

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
    # The asymmetry applied to ownership: an empty listing is not evidence
    # that the bucket belongs to somebody else.
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
