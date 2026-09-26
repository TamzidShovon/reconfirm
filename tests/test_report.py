"""Rendering, including the ASCII output constraint."""

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


def test_non_ascii_evidence_does_not_crash_the_console():
    # Evidence and reasons can carry text pulled straight from a live
    # response - a takeover fingerprint's surrounding HTML, a secret's
    # captured value - which is not guaranteed to be ASCII or even
    # cp1252-encodable. Seen live: CJK characters in a takeover snippet and
    # in an unredacted secrets.py match both crashed a cp1252 console.
    stream = io.StringIO()
    report.render([
        confirmed(
            "takeover", "http://x.example.com", "serves an unclaimed page",
            u"找不到页面 No such app 页面不存在",
        ),
        unverified(
            "secrets", "http://y.example.com/app.js", "assignment matched",
            u"reason with a café and 中文 in it",
        ),
    ], stream=stream, show_discarded=True)
    out = stream.getvalue()
    out.encode("ascii")  # must not raise
    out.encode("cp1252")  # must not raise
    assert "No such app" in out
    assert "assignment matched" in out


def test_non_ascii_summary_does_not_crash_the_console():
    stream = io.StringIO()
    report.render([
        confirmed("takeover", "http://x.example.com",
                  u"unclaimed page — café ‘quoted’", "evidence"),
    ], stream=stream)
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
