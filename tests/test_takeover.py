"""
Fingerprint matching, and the catch-all case that defeats it.

The second test here is the one that matters: a host answering every path with
the same page will happily serve a page containing a takeover marker, and a
check that only substring-matches reports it.
"""

from reconfirm.checks import Target, takeover
from reconfirm.confidence import CONFIRMED, DISCARDED, UNVERIFIED
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
    # The check proves the provider serves its unclaimed page; whether the name
    # can be registered is a separate, manual step, and the wording says so.
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
    # "No such app" 200KB into an application bundle is a coincidence, not a
    # provider's error page.
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
