"""Address lookup, caching, and the --ip surface."""

import io
import json
import socket

import pytest

from reconfirm import net, report
from reconfirm.cli import _print_addresses, build_parser
from reconfirm.confidence import confirmed
from reconfirm.net import NXDOMAIN, RESOLVED, UNKNOWN, addresses, lookup


def test_loopback_resolves_to_itself():
    found, state = lookup("127.0.0.1")
    assert state == RESOLVED
    assert "127.0.0.1" in found


def test_addresses_are_deduplicated_and_sorted(monkeypatch):
    def many(*_a, **_kw):
        return [
            (None, None, None, None, ("93.184.216.34", 0)),
            (None, None, None, None, ("93.184.216.34", 0)),
            (None, None, None, None, ("10.0.0.1", 0)),
        ]

    monkeypatch.setattr(net.socket, "getaddrinfo", many)
    assert addresses("example.com") == ["10.0.0.1", "93.184.216.34"]


def test_ipv6_and_ipv4_come_back_together(monkeypatch):
    def both(*_a, **_kw):
        return [
            (None, None, None, None, ("93.184.216.34", 0)),
            (None, None, None, None, ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]

    monkeypatch.setattr(net.socket, "getaddrinfo", both)
    found = addresses("example.com")
    assert len(found) == 2
    assert any(":" in a for a in found)


def test_nxdomain_yields_no_addresses():
    found, state = lookup("nonexistent-subdomain-for-tests.invalid")
    assert state == NXDOMAIN
    assert found == []


def test_temporary_failure_is_not_nxdomain(monkeypatch):
    def temporary(*_a, **_kw):
        raise socket.gaierror(getattr(socket, "EAI_AGAIN", 11002), "try again")

    monkeypatch.setattr(net.socket, "getaddrinfo", temporary)
    found, state = lookup("example.com")
    assert state == UNKNOWN
    assert found == []


def test_lookup_is_cached(monkeypatch):
    calls = []

    def counting(*_a, **_kw):
        calls.append(1)
        return [(None, None, None, None, ("1.2.3.4", 0))]

    monkeypatch.setattr(net.socket, "getaddrinfo", counting)
    lookup("example.com")
    lookup("example.com")
    addresses("example.com")
    assert len(calls) == 1


def test_cache_is_keyed_without_the_port(monkeypatch):
    calls = []

    def counting(*_a, **_kw):
        calls.append(1)
        return [(None, None, None, None, ("1.2.3.4", 0))]

    monkeypatch.setattr(net.socket, "getaddrinfo", counting)
    lookup("example.com")
    lookup("example.com:8443")
    assert len(calls) == 1


def test_clearing_the_cache_forces_a_fresh_lookup(monkeypatch):
    calls = []

    def counting(*_a, **_kw):
        calls.append(1)
        return [(None, None, None, None, ("1.2.3.4", 0))]

    monkeypatch.setattr(net.socket, "getaddrinfo", counting)
    lookup("example.com")
    net.clear_lookup_cache()
    lookup("example.com")
    assert len(calls) == 2


# --- CLI surface ---

@pytest.mark.parametrize("flag", ["-ip", "--ip"])
@pytest.mark.parametrize("command", ["enumerate", "scan"])
def test_both_spellings_accepted_on_both_commands(command, flag):
    args = build_parser().parse_args([command, "example.com", flag])
    assert args.ip is True


def test_ip_is_off_by_default():
    assert build_parser().parse_args(["scan", "example.com"]).ip is False


def test_address_table_groups_shared_hosts(capsys):
    _print_addresses({
        "a.example.com": ["1.2.3.4"],
        "b.example.com": ["1.2.3.4"],
        "c.example.com": ["5.6.7.8"],
        "d.example.com": [],
    })
    out = capsys.readouterr().out
    assert "4 hosts on 3 distinct address sets" in out
    # The shared address leads, and both of its names sit under it.
    assert out.index("1.2.3.4") < out.index("5.6.7.8")
    assert out.index("a.example.com") > out.index("1.2.3.4")
    assert "-" in out  # the unresolved host


def test_address_table_is_ascii(capsys):
    _print_addresses({"a.example.com": ["1.2.3.4"]})
    capsys.readouterr().out.encode("cp1252")


# --- JSON ---

def test_addresses_absent_from_json_when_not_requested():
    payload = report.to_json([confirmed("c", "t", "s", "e")], "example.com")
    # Absent, not empty: {} would read as "these hosts have no addresses".
    assert "addresses" not in payload


def test_addresses_present_in_json_when_requested():
    payload = report.to_json(
        [confirmed("c", "t", "s", "e")], "example.com",
        addresses={"a.example.com": ["1.2.3.4"]},
    )
    assert payload["addresses"] == {"a.example.com": ["1.2.3.4"]}
    json.dumps(payload)


def test_json_addresses_round_trip(tmp_path):
    path = tmp_path / "out.json"
    report.write_json(
        str(path), [confirmed("c", "t", "s", "e")], "example.com",
        addresses={"b.example.com": ["9.9.9.9"], "a.example.com": ["1.1.1.1"]},
    )
    restored = json.loads(path.read_text(encoding="utf-8"))
    assert list(restored["addresses"]) == ["a.example.com", "b.example.com"]
