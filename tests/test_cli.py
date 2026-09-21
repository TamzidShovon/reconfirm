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
    assert "127.0.0.1:59194" in Scope(["127.0.0.1"])


def test_partition_by_resolution_splits_live_from_dead():
    from reconfirm.cli import _partition_by_resolution

    live, dead = _partition_by_resolution([
        "127.0.0.1",
        "nonexistent-subdomain-for-tests.invalid",
        "localhost",
    ])
    assert "127.0.0.1" in live
    assert "nonexistent-subdomain-for-tests.invalid" in dead


def test_partition_preserves_order():
    from reconfirm.cli import _partition_by_resolution

    live, _dead = _partition_by_resolution(["127.0.0.1", "localhost"])
    assert live == ["127.0.0.1", "localhost"]


def test_hosts_file_with_a_utf8_bom_is_read_correctly(tmp_path):
    # Read as plain utf-8, a BOM leaves U+FEFF on the first hostname.
    path = tmp_path / "hosts.txt"
    path.write_bytes(b"\xef\xbb\xbfapi.example.com\r\nwww.example.com\r\n")

    with open(path, encoding="utf-8-sig") as fh:
        hosts = [line.strip() for line in fh if line.strip()]

    assert hosts == ["api.example.com", "www.example.com"]
    assert hosts[0] in Scope(["example.com"])


def test_hosts_file_without_a_bom_is_unaffected(tmp_path):
    path = tmp_path / "hosts.txt"
    path.write_bytes(b"api.example.com\nwww.example.com\n")

    with open(path, encoding="utf-8-sig") as fh:
        hosts = [line.strip() for line in fh if line.strip()]

    assert hosts == ["api.example.com", "www.example.com"]
