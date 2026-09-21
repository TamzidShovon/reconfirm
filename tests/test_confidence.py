"""The state rules, asserted directly."""

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
    # An empty capture group can yield a technically non-empty string.
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
    # A transport failure must never read as "ruled out".
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
