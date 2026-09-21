"""
Rendering results to a terminal and to JSON.

The console output groups by state rather than by check, because the state is
what determines what the reader does next: act on CONFIRMED, look at
UNVERIFIED by hand, ignore DISCARDED unless auditing the tool itself. Grouping
by check would scatter the three across the whole report and undo the point of
separating them.

DISCARDED is hidden by default and printed on request. It is the tool showing
its work — every entry is a claim it declined to make and the reason — which is
useful when tuning a check or arguing about a rule, and noise otherwise.
"""

import json
import os
import sys
from datetime import datetime, timezone

from .confidence import CONFIRMED, DISCARDED, STATES, UNVERIFIED, sort_results, tally

# ASCII only, deliberately. The Windows console defaults to cp1252, which
# cannot encode an em dash or an arrow; output written with them either raises
# UnicodeEncodeError or prints replacement characters, and a report nobody can
# read on the platform it ran on is not a report.
HEADINGS = {
    CONFIRMED: "CONFIRMED - evidence supports the claim",
    UNVERIFIED: "UNVERIFIED - plausible, proof was inconclusive",
    DISCARDED: "DISCARDED - actively disproved",
}

_COLORS = {CONFIRMED: "\033[32m", UNVERIFIED: "\033[33m", DISCARDED: "\033[90m"}
_RESET = "\033[0m"


def _use_color(stream):
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _wrap(text, width, indent, hanging=None):
    """Minimal greedy wrapper.

    `hanging` is the indent for continuation lines; it defaults to matching
    `indent` in width so that a marker like "-> " appears once and the rest of
    the paragraph stays aligned under it rather than repeating it.
    """
    if hanging is None:
        hanging = " " * len(indent)
    lines, current = [], indent
    for word in text.split():
        if len(current) + len(word) > width and current.strip():
            lines.append(current.rstrip())
            current = hanging + word + " "
        else:
            current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return lines


def render(results, stream=None, show_discarded=False, width=96, notes=None):
    stream = stream or sys.stdout
    color = _use_color(stream)
    results = sort_results(results)
    counts = tally(results)

    states = [CONFIRMED, UNVERIFIED] + ([DISCARDED] if show_discarded else [])

    for state in states:
        group = [r for r in results if r.state == state]
        if not group:
            continue
        heading = "%s  (%d)" % (HEADINGS[state], len(group))
        rule = "-" * min(width, len(heading))
        if color:
            heading = _COLORS[state] + heading + _RESET
        stream.write("\n" + heading + "\n")
        stream.write(rule + "\n")

        for r in group:
            stream.write("  [%s] %s\n" % (r.check, r.target))
            for line in _wrap(r.summary, width, "      "):
                stream.write(line + "\n")
            if r.evidence:
                for line in r.evidence.splitlines()[:8]:
                    stream.write("      | %s\n" % line[:width - 8])
            if r.reason:
                for line in _wrap(r.reason, width, "      -> ", hanging=" " * 9):
                    stream.write(line + "\n")
            stream.write("\n")

    summary = "%d confirmed, %d unverified, %d discarded" % (
        counts[CONFIRMED], counts[UNVERIFIED], counts[DISCARDED],
    )
    if not show_discarded and counts[DISCARDED]:
        summary += "  (re-run with --show-discarded to see what was ruled out and why)"
    stream.write(summary + "\n")

    for note in notes or []:
        stream.write("note: %s\n" % note)


def to_json(results, domain, notes=None, requests_made=None):
    results = sort_results(results)
    return {
        "domain": domain,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": tally(results),
        "notes": list(notes or []),
        "requests_made": requests_made or {},
        "results": [r.as_dict() for r in results],
    }


def write_json(path, results, domain, notes=None, requests_made=None):
    payload = to_json(results, domain, notes, requests_made)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path
