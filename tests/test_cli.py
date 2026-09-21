"""
The CLI's host handling.

The scope filter in cmd_scan silently dropped every `host:port` line read from
--hosts-from, because it compared the raw line against bare scope domains
while requests compared a urlparse'd hostname. A run against four live hosts
reported "probing 0 hosts" and exited 0 with nothing found, which is the worst
possible failure mode for this tool: a clean bill of health it never earned.
"""

import pytest

from reconfirm.net import Scope, hostname_of


@pytest.mark.parametrize("raw, expected", [
    ("example.com", "example.com"),
    ("example.com:8443", "example.com"),
    ("127.0.0.1:59194", "127.0.0.1"),
    ("EXAMPLE.COM:443", "example.com"),
    ("example.com.", "example.com"),
    ("[::1]:8080", "::1"),
    ("::1", "::1"),
    ("", ""),
])
def test_hostname_of_strips_ports(raw, expected):
    assert hostname_of(raw) == expected


@pytest.mark.parametrize("host", [
    "example.com",
    "example.com:8443",
    "api.example.com:443",
])
def test_hosts_with_ports_stay_in_scope(host):
    assert host in Scope(["example.com"])


def test_port_does_not_smuggle_a_host_into_scope():
    # Stripping the port must not weaken the boundary it is stripping for.
    assert "evil.net:443" not in Scope(["example.com"])
    assert "notexample.com:443" not in Scope(["example.com"])


def test_loopback_with_port_matches_loopback_scope():
    # The exact case the controlled-target run exercises.
    assert "127.0.0.1:59194" in Scope(["127.0.0.1"])
