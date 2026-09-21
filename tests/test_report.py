"""
Rendering, including the encoding constraint.

The cp1252 test is a regression guard, not a style preference. A previous
version of this tooling wrote an arrow character into its findings output and
died with UnicodeEncodeError on the Windows console — after the scan had run.
Losing results at the print step is an expensive way to learn that the default
console encoding is not UTF-8.
"""

import io
import json

from reconfirm import report
from reconfirm.confidence import CONFIRMED, confirmed, discarded, unverified


def _sample():
    return [
        confirmed("takeover", "https://a.example.com", "serves an unclaimed page", "<h1>404</h1>"),
        unverified("buckets", "https://b.s3.amazonaws.com", "ownership unproven", "the bucket is empty"),
        discarded("secrets", "https://c.example.com/app.js", "rejected", "the value is a placeholder"),
    ]


def test_output_is_encodable_on_a_windows_console():
    stream = io.StringIO()
    report.render(_sample(), stream=stream, show_discarded=True)
    # Raises UnicodeEncodeError if any character is outside cp1252.
    stream.getvalue().encode("cp1252")


def test_output_is_pure_ascii():
    stream = io.StringIO()
    report.render(_sample(), stream=stream, show_discarded=True)
    stream.getvalue().encode("ascii")


def test_discarded_hidden_by_default():
    stream = io.StringIO()
    report.render(_sample(), stream=stream)
    output = stream.getvalue()
    assert "app.js" not in output
    assert "--show-discarded" in output


def test_discarded_shown_on_request():
    stream = io.StringIO()
    report.render(_sample(), stream=stream, show_discarded=True)
    output = stream.getvalue()
    assert "app.js" in output
    assert "placeholder" in output


def test_counts_line_reports_every_state():
    stream = io.StringIO()
    report.render(_sample(), stream=stream)
    assert "1 confirmed, 1 unverified, 1 discarded" in stream.getvalue()


def test_reason_marker_appears_once_when_wrapped():
    long_reason = "the bucket is listable but empty so nothing evidences who owns it " * 3
    stream = io.StringIO()
    report.render(
        [unverified("buckets", "https://x.example.com", "ownership unproven", long_reason)],
        stream=stream,
    )
    body = stream.getvalue()
    assert body.count("->") == 1


def test_notes_are_printed():
    stream = io.StringIO()
    report.render(_sample(), stream=stream, notes=["crt.sh was rate-limiting"])
    assert "note: crt.sh was rate-limiting" in stream.getvalue()


def test_json_payload_round_trips():
    payload = report.to_json(_sample(), "example.com", notes=["a note"], requests_made={"h": 4})
    restored = json.loads(json.dumps(payload))
    assert restored["domain"] == "example.com"
    assert restored["counts"][CONFIRMED] == 1
    assert restored["notes"] == ["a note"]
    assert len(restored["results"]) == 3


def test_json_confirmed_entry_carries_its_evidence():
    payload = report.to_json(_sample(), "example.com")
    entry = next(r for r in payload["results"] if r["state"] == CONFIRMED)
    assert entry["evidence"]
