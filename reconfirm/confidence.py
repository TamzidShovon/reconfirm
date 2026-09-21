"""Result states and the rules for reaching them.

    CONFIRMED   an independent check produced supporting evidence
    UNVERIFIED  plausible, but the check meant to prove it was inconclusive
    DISCARDED   a check actively disproved the claim

Inconclusive outcomes resolve to UNVERIFIED, never DISCARDED. CONFIRMED
requires evidence, enforced in Result.__post_init__.

See docs/CONFIDENCE.md for the rationale.
"""

from dataclasses import dataclass

CONFIRMED = "confirmed"
UNVERIFIED = "unverified"
DISCARDED = "discarded"

STATES = (CONFIRMED, UNVERIFIED, DISCARDED)

# Actionable first, ruled out last.
RANK = {CONFIRMED: 0, UNVERIFIED: 1, DISCARDED: 2}

# Evidence is quoted verbatim into reports, so it is capped.
MAX_EVIDENCE = 600


class ConfidenceError(ValueError):
    """Raised when a Result violates the state rules."""


@dataclass
class Result:
    check: str
    target: str
    state: str
    summary: str
    evidence: str = ""
    reason: str = ""

    def __post_init__(self):
        if self.state not in STATES:
            raise ConfidenceError(
                "unknown state %r (expected one of %s)" % (self.state, ", ".join(STATES))
            )
        self.evidence = (self.evidence or "").strip()[:MAX_EVIDENCE]
        if self.state == CONFIRMED and not self.evidence:
            raise ConfidenceError(
                "%s claimed CONFIRMED for %s with no evidence" % (self.check, self.target)
            )
        if self.state != CONFIRMED and not self.reason:
            raise ConfidenceError(
                "%s returned %s for %s without a reason" % (self.check, self.state, self.target)
            )

    def as_dict(self):
        d = {
            "check": self.check,
            "target": self.target,
            "state": self.state,
            "summary": self.summary,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        if self.reason:
            d["reason"] = self.reason
        return d


def confirmed(check, target, summary, evidence):
    return Result(check, target, CONFIRMED, summary, evidence=evidence)


def unverified(check, target, summary, reason):
    return Result(check, target, UNVERIFIED, summary, reason=reason)


def discarded(check, target, summary, reason):
    return Result(check, target, DISCARDED, summary, reason=reason)


def inconclusive(check, target, summary, error):
    """A check that could not complete. Resolves to UNVERIFIED."""
    if isinstance(error, BaseException):
        error = "%s: %s" % (type(error).__name__, error)
    return unverified(check, target, summary, "could not complete check - %s" % error)


def sort_results(results):
    return sorted(results, key=lambda r: (RANK[r.state], r.check, r.target))


def tally(results):
    counts = {state: 0 for state in STATES}
    for r in results:
        counts[r.state] += 1
    return counts
