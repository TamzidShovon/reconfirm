"""Rendering results to a terminal and to JSON.

Output groups by state, since the state determines what the reader does
next. DISCARDED is hidden unless asked for.
"""

import json
import os
import sys
from datetime import datetime, timezone

from .confidence import CONFIRMED, DISCARDED, STATES, UNVERIFIED, sort_results, tally

# ASCII only: the Windows console defaults to cp1252, which cannot encode
# an em dash or an arrow. Enforced by tests/test_encoding.py.
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


def _write(stream, text):
    """Write, dropping anything the Windows console (cp1252) cannot show.

    Evidence and reasons often quote text pulled straight from a live
    response - a takeover fingerprint's surrounding HTML, a secret's
    captured value - and that text is not guaranteed to be ASCII, let alone
    encodable in cp1252. Seen live: CJK characters landing in an unredacted
    slice of a secrets.py match crashed the console outright. JSON output
    keeps full fidelity (see to_json below); only this renderer needs it
    stripped, so the check modules stay free to collect what they find.
    """
    stream.write(text.encode("ascii", "ignore").decode("ascii"))


def _wrap(text, width, indent, hanging=None):
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
        _write(stream, "\n" + heading + "\n")
        _write(stream, rule + "\n")

        for r in group:
            _write(stream, "  [%s] %s\n" % (r.check, r.target))
            for line in _wrap(r.summary, width, "      "):
                _write(stream, line + "\n")
            if r.evidence:
                for line in r.evidence.splitlines()[:8]:
                    _write(stream, "      | %s\n" % line[:width - 8])
            if r.reason:
                for line in _wrap(r.reason, width, "      -> ", hanging=" " * 9):
                    _write(stream, line + "\n")
            _write(stream, "\n")

    summary = "%d confirmed, %d unverified, %d discarded" % (
        counts[CONFIRMED], counts[UNVERIFIED], counts[DISCARDED],
    )
    if not show_discarded and counts[DISCARDED]:
        summary += "  (re-run with --show-discarded to see what was ruled out and why)"
    _write(stream, summary + "\n")

    for note in notes or []:
        _write(stream, "note: %s\n" % note)


def to_json(results, domain, notes=None, requests_made=None, addresses=None):
    results = sort_results(results)
    payload = {
        "domain": domain,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": tally(results),
        "notes": list(notes or []),
        "requests_made": requests_made or {},
        "results": [r.as_dict() for r in results],
    }
    # Absent unless --ip was passed: {} would read as "no addresses" rather
    # than "not looked up".
    if addresses:
        payload["addresses"] = {h: list(a) for h, a in sorted(addresses.items())}
    return payload


def write_json(path, results, domain, notes=None, requests_made=None, addresses=None):
    payload = to_json(results, domain, notes, requests_made, addresses)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path
