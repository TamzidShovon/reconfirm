"""Enumeration, and what it does when its sources fail."""

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


def test_crtsh_json_null_is_a_note_not_a_crash():
    # A bare "null" body is valid JSON, so it doesn't hit the non-JSON path,
    # but iterating None crashes if nothing checks the shape first.
    class NullResponse:
        status_code = 200
        text = "null"

        def json(self):
            return None

    session = FakeSession({
        "crt.sh": (NullResponse(), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, notes = sources.enumerate_hosts(session, "example.com")
    assert hosts == ["example.com"]
    assert any("not a list" in n for n in notes)


def test_crtsh_json_error_object_is_a_note_not_a_crash():
    # A JSON object instead of the documented array: iterating a dict yields
    # its keys (strings), and entry.get(...) on a string crashes.
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload={"error": "not found"}), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, notes = sources.enumerate_hosts(session, "example.com")
    assert hosts == ["example.com"]
    assert any("not a list" in n for n in notes)


def test_crtsh_non_object_entries_are_skipped_not_crashed():
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[
            "not-a-dict", {"name_value": "api.example.com"},
        ]), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "example.com")
    assert "api.example.com" in hosts


def test_mixed_case_domain_still_matches_crtsh_results():
    # "Example.COM" as typed on the CLI must not silently discard every
    # crt.sh result for it - _clean() lowercases each candidate before
    # comparing it against the domain, so the domain has to be lowercased
    # too, or nothing it finds will ever match.
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[{"name_value": "api.example.com"}]), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "Example.COM")
    assert "api.example.com" in hosts
    assert "example.com" in hosts


def test_trailing_dot_domain_still_matches_crtsh_results():
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[{"name_value": "api.example.com"}]), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "example.com.")
    assert "api.example.com" in hosts
    assert "example.com" in hosts


def test_wayback_can_be_skipped():
    session = FakeSession({"crt.sh": (FakeResponse(200, payload=[]), None)})
    sources.enumerate_hosts(session, "example.com", use_wayback=False)
    assert not any("archive.org" in c for c in session.calls)


def test_concatenation_artifacts_are_rejected():
    # Observed in a real Wayback query.
    assert sources._clean("testasp.vulnweb.comtestasp.vulnweb.com", "vulnweb.com") is None


def test_encoding_artifacts_are_left_to_dns_not_guessed_at():
    # "2ftestphp" is %2f + a label; "2fa" is a real subdomain. No pattern
    # separates them, so both pass through and the caller resolves them.
    assert sources._clean("2ftestphp.vulnweb.com", "vulnweb.com") == "2ftestphp.vulnweb.com"
    assert sources._clean("2fa.vulnweb.com", "vulnweb.com") == "2fa.vulnweb.com"


def test_legitimate_hosts_survive():
    for name in ["testphp.vulnweb.com", "rest.vulnweb.com", "2fa.vulnweb.com",
                 "api-v2.vulnweb.com", "3d.vulnweb.com"]:
        assert sources._clean(name, "vulnweb.com") == name, name


def test_ip_target_skips_both_passive_sources():
    # crt.sh and the Wayback Machine are indexes of names; querying them for
    # an address spends two requests to be told 404.
    class NoNetwork:
        def get_external(self, *a, **kw):
            raise AssertionError("an IP target must not query a passive source")

    hosts, notes = sources.enumerate_hosts(NoNetwork(), "45.33.32.156")
    assert hosts == ["45.33.32.156"]
    assert notes == []


def test_ipv6_target_also_skips_passive_sources():
    class NoNetwork:
        def get_external(self, *a, **kw):
            raise AssertionError("an IP target must not query a passive source")

    hosts, _notes = sources.enumerate_hosts(NoNetwork(), "::1")
    assert hosts == ["::1"]


def test_domain_target_still_queries_sources():
    session = FakeSession({
        "crt.sh": (FakeResponse(200, payload=[{"name_value": "api.example.com"}]), None),
        "archive.org": (FakeResponse(200, text=""), None),
    })
    hosts, _notes = sources.enumerate_hosts(session, "example.com")
    assert "api.example.com" in hosts
    assert session.calls
