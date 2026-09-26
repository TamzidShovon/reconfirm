"""Fingerprint matching, and the catch-all case that defeats it."""

from reconfirm.checks import Target, takeover
from reconfirm.confidence import CONFIRMED, DISCARDED, UNVERIFIED
from reconfirm.net import BudgetExhausted, Scope, Session
from tests.conftest import Routes


def _target(origin):
    return Target(domain="127.0.0.1", hosts=[origin.split("//")[1]])


def test_marker_on_a_normal_404_host_is_confirmed(server, session):
    routes = Routes()
    routes.add("/", "<html><body>There isn't a GitHub Pages site here.</body></html>")
    origin = server(routes)

    results = takeover.run(session, _target(origin))
    confirmed = [r for r in results if r.state == CONFIRMED]
    assert len(confirmed) == 1
    assert "GitHub Pages" in confirmed[0].summary
    assert "GitHub Pages site here" in confirmed[0].evidence


def test_summary_claims_only_what_was_shown(server, session):
    routes = Routes().add("/", "<html>No such app</html>")
    origin = server(routes)

    results = takeover.run(session, _target(origin))
    confirmed = [r for r in results if r.state == CONFIRMED]
    # Whether the name can be registered is a separate, manual step.
    assert "check whether the name can still be registered" in confirmed[0].summary


def test_marker_from_a_catchall_is_discarded(server, session):
    # Every path, including one that cannot exist, returns the same page.
    routes = Routes().set_catchall("<html><body>No such app</body></html>")
    origin = server(routes)

    results = takeover.run(session, _target(origin))
    assert [r.state for r in results] == [DISCARDED]
    assert "catch-all" in results[0].summary
    assert "served for every request" in results[0].reason


def test_unreachable_host_is_unverified(session):
    # A dead A record and a dangling CNAME look identical from here.
    target = Target(domain="127.0.0.1", hosts=["127.0.0.1:1"])
    results = takeover.run(session, target)
    assert [r.state for r in results] == [UNVERIFIED]
    assert "did not respond" in results[0].summary


def test_marker_deep_in_a_bundle_is_ignored(server, session):
    # A marker deep in a bundle is a coincidence, not a provider page.
    body = "<html><script>" + ("x" * 200000) + "\n// No such app\n</script></html>"
    routes = Routes().add("/", body)
    origin = server(routes)

    results = takeover.run(session, _target(origin))
    assert not [r for r in results if r.state == CONFIRMED]


def test_one_result_per_host(server, session):
    # Two markers in one body must not produce two findings for one host.
    routes = Routes().add("/", "<html>No such app. NoSuchBucket.</html>")
    origin = server(routes)

    results = takeover.run(session, _target(origin))
    assert len(results) == 1


def test_budget_exhaustion_on_one_host_does_not_skip_the_rest(monkeypatch, session):
    # per_host_budget is tracked separately per hostname (Session._host_counts
    # is keyed by host), so host B still has its own full budget even though
    # host A just spent its own. The loop must not treat one host's exhaustion
    # as a reason to stop probing every host after it.
    calls = []

    def fake_fetch_site(_session, host, **_kw):
        calls.append(host)
        if host == "a.invalid":
            raise BudgetExhausted("a.invalid: per-host budget of 1 requests is spent")
        return "http://b.invalid", None, "connection refused"

    monkeypatch.setattr(takeover, "fetch_site", fake_fetch_site)
    monkeypatch.setattr(takeover, "resolves", lambda h: True)

    target = Target(domain="invalid", hosts=["a.invalid", "b.invalid"])
    results = takeover.run(session, target)

    assert calls == ["a.invalid", "b.invalid"]
    assert [r.target for r in results] == ["a.invalid", "b.invalid"]


def test_budget_exhausted_during_the_catchall_probe_does_not_crash(server):
    # The catch-all probe is its own request, fired only once a marker
    # matches. A marker match and a budget that runs out right then must
    # degrade to a result, not an unhandled exception through the whole scan.
    routes = Routes().add("/", "<html>No such app</html>")
    origin = server(routes)

    # The test server is HTTP-only: fetch_site spends one request failing
    # over https and one succeeding over http, leaving nothing for the
    # catch-all probe the marker match is about to trigger.
    tight_session = Session(Scope(["127.0.0.1"]), min_interval=0.0, timeout=5,
                             per_host_budget=2)

    results = takeover.run(tight_session, _target(origin))

    assert [r.state for r in results] == [UNVERIFIED]
    assert "could not rule out a catch-all" in results[0].summary
