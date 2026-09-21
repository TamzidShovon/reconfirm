"""
Enumeration, and what it does when its sources fail.

The seeding rule exists because of a live run where crt.sh answered 502 and
the Wayback Machine answered 503 at the same moment. Enumeration returned an
empty list, so nothing was probed, and the run printed "0 confirmed, 0
unverified, 0 discarded" and exited 0 — a result indistinguishable from
a target with nothing wrong with it.
"""

from reconfirm import sources


class FakeResponse:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Session stand-in that answers external calls from a script."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get_external(self, url, **kw):
        self.calls.append(url)
        for fragment, outcome in self.responses.items():
            if fragment in url:
                return outcome
        return None, "no stub for %s" % url


def test_apex_is_seeded_even_when_every_source_fails():
    session = FakeSession({
        "crt.sh": (FakeResponse(502), None),
        "archive.org": (FakeResponse(503), None),
    })
    hosts, notes = sources.enumerate_hosts(session, "example.com")
    assert hosts == ["example.com"]
    assert len(notes) == 2


def test_source_failures_are_reported_not_swallowed():
    session = FakeSession({
        "crt.sh": (FakeResponse(502), None),
        "archive.org": (FakeResponse(503), None),
    })
    _hosts, notes = sources.enumerate_hosts(session, "example.com")
    assert any("502" in n for n in notes)
    assert any("503" in n for n in notes)


def test_apex_is_not_duplicated_when_a_source_also_returns_it():
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[{"name_value": "api.example.com"}]), None),
        "archive.org": (FakeResponse(200, text="http://api.example.com/x"), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "example.com")
    assert hosts == ["api.example.com", "example.com"]
    assert len(hosts) == len(set(hosts))


def test_wildcard_and_out_of_scope_names_are_dropped():
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[
            {"name_value": "*.example.com\napi.example.com\nevil.net"},
        ]), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "example.com")
    assert "evil.net" not in hosts
    assert "*.example.com" not in hosts
    assert "api.example.com" in hosts


def test_non_json_from_crtsh_is_a_note_not_a_crash():
    # crt.sh serves an HTML error page under load rather than a JSON error.
    session = FakeSession({
        "crt.sh": (FakeResponse(200, text="<html>rate limited</html>"), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, notes = sources.enumerate_hosts(session, "example.com")
    assert hosts == ["example.com"]
    assert any("rate-limiting" in n for n in notes)


def test_wayback_can_be_skipped():
    session = FakeSession({"crt.sh": (FakeResponse(200, payload=[]), None)})
    sources.enumerate_hosts(session, "example.com", use_wayback=False)
    assert not any("archive.org" in c for c in session.calls)
