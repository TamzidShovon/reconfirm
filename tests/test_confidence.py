"""
The state rules, asserted directly.

These are the cheapest tests in the suite and the ones most worth having: every
rule here is enforced in a constructor, so a check that violates one fails at
the moment it builds the Result rather than by emitting a bad claim into a
report.
"""

import pytest

from reconfirm.confidence import (
    CONFIRMED,
    DISCARDED,
    UNVERIFIED,
    ConfidenceError,
    Result,
    confirmed,
    discarded,
    inconclusive,
    sort_results,
    tally,
    unverified,
)


def test_confirmed_requires_evidence():
    with pytest.raises(ConfidenceError, match="no evidence"):
        Result("c", "t", CONFIRMED, "found something")


def test_confirmed_rejects_whitespace_evidence():
    # Guards the case where a check interpolates an empty capture group and
    # gets a string that is technically non-empty.
    with pytest.raises(ConfidenceError, match="no evidence"):
        Result("c", "t", CONFIRMED, "found something", evidence="   \n  ")


def test_non_confirmed_requires_a_reason():
    with pytest.raises(ConfidenceError, match="without a reason"):
        Result("c", "t", UNVERIFIED, "maybe something")


def test_unknown_state_rejected():
    with pytest.raises(ConfidenceError, match="unknown state"):
        Result("c", "t", "probably", "found something", evidence="x")


def test_evidence_is_capped():
    r = confirmed("c", "t", "s", "x" * 5000)
    assert len(r.evidence) == 600


def test_inconclusive_lands_on_unverified_not_discarded():
    # The asymmetry, stated as a test. A transport failure must never be
    # allowed to read as "ruled out".
    r = inconclusive("c", "t", "s", ConnectionError("connection reset"))
    assert r.state == UNVERIFIED
    assert "ConnectionError" in r.reason


def test_inconclusive_accepts_a_plain_string():
    r = inconclusive("c", "t", "s", "timed out")
    assert r.state == UNVERIFIED
    assert "timed out" in r.reason


def test_sort_puts_actionable_first():
    results = [
        discarded("c", "t3", "s", "r"),
        unverified("c", "t2", "s", "r"),
        confirmed("c", "t1", "s", "e"),
    ]
    assert [r.target for r in sort_results(results)] == ["t1", "t2", "t3"]


def test_tally_counts_every_state():
    results = [
        confirmed("c", "t", "s", "e"),
        unverified("c", "t", "s", "r"),
        unverified("c", "t", "s", "r"),
    ]
    assert tally(results) == {CONFIRMED: 1, UNVERIFIED: 2, DISCARDED: 0}


def test_as_dict_omits_empty_fields():
    d = confirmed("c", "t", "s", "e").as_dict()
    assert "reason" not in d
    assert d["evidence"] == "e"
