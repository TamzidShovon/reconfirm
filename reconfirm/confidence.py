"""
The three states a result can hold, and the rules for reaching them.

Recon tooling almost universally reports in two states: found, or not found.
That collapses two very different situations — "I proved this" and "I saw
something that might be this but could not prove it" — into a single word, and
the person reading the output has no way to pull them back apart. Most of the
time wasted triaging a scanner's results comes from that collapse.

So there are three states here, and one deliberate asymmetry between them:

    CONFIRMED   an independent check produced evidence supporting the claim
    UNVERIFIED  the claim is plausible; the check meant to prove it was
                inconclusive
    DISCARDED   a check actively disproved the claim

The asymmetry: an inconclusive outcome always resolves to UNVERIFIED, never to
DISCARDED. A timeout, a connection reset, a WAF block and a rate-limit all
present as "no evidence found", and treating absent evidence as evidence of
absence is precisely how a scanner silently drops the one real result in a run.
DISCARDED is reserved for claims positively shown to be false — a secret whose
value is a known placeholder, a response byte-identical to the host's catch-all.

CONFIRMED additionally requires evidence to be present, and Result enforces
that in __post_init__ rather than trusting the caller. A "confirmed" with
nothing behind it is the exact failure this module exists to prevent, and a
check that forgets to attach its evidence should fail loudly during its own
tests rather than quietly emit an unsupported claim.
"""

from dataclasses import dataclass

CONFIRMED = "confirmed"
UNVERIFIED = "unverified"
DISCARDED = "discarded"

STATES = (CONFIRMED, UNVERIFIED, DISCARDED)

# Sort order for output: what you can act on first, what was ruled out last.
RANK = {CONFIRMED: 0, UNVERIFIED: 1, DISCARDED: 2}

# Evidence is quoted verbatim into reports, so it is capped. 600 chars is
# enough for a bucket listing or a cert SAN block without turning a JSON
# report into a copy of the target's homepage.
MAX_EVIDENCE = 600


class ConfidenceError(ValueError):
    """Raised when a Result violates the state rules — a bug in a check."""


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
    """A check that could not complete.

    Exists so the asymmetry is something a check calls by name instead of
    something it has to remember. Anywhere a check catches an exception or
    reads a transport error, this is the correct exit.
    """
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
