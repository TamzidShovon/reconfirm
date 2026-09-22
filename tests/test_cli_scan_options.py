"""-p/--ports and --select as parsed and dispatched by cmd_scan."""

import io

from reconfirm.checks import DEFAULT_CHECKS
from reconfirm.checks import ports as ports_check
from reconfirm.cli import _requested_checks, build_parser, cmd_scan


# --- _requested_checks ---

def test_no_ports_leaves_the_default_set_untouched():
    assert _requested_checks(None, None) == list(DEFAULT_CHECKS)


def test_explicit_checks_are_used_as_given():
    assert _requested_checks(["takeover"], None) == ["takeover"]


def test_ports_spec_alone_means_ports_only():
    # Not default-plus-ports: that turns "scan these ports" into a full recon
    # sweep, which on a live run meant probing third-party storage endpoints
    # nobody asked about.
    assert _requested_checks(None, "80,443") == ["ports"]


def test_ports_spec_with_explicit_checks_runs_both():
    result = _requested_checks(["takeover", "secrets"], "80")
    assert result == ["takeover", "secrets", "ports"]


def test_ports_spec_adds_ports_to_an_explicit_list():
    assert _requested_checks(["secrets"], "80") == ["secrets", "ports"]


def test_ports_spec_does_not_duplicate_an_explicit_ports_check():
    assert _requested_checks(["ports"], "80") == ["ports"]


def test_empty_string_spec_still_counts_as_a_request():
    # "" means "use the default port list", not "no ports were asked for".
    assert "ports" in _requested_checks(None, "")


# --- argparse ---

def test_ports_defaults_to_none():
    args = build_parser().parse_args(["scan", "example.com"])
    assert args.ports is None


def test_short_and_long_port_flags():
    for flag in ("-p", "--ports"):
        args = build_parser().parse_args(["scan", "example.com", flag, "80,443"])
        assert args.ports == "80,443"


def test_select_defaults_to_off():
    args = build_parser().parse_args(["scan", "example.com"])
    assert args.select is False


def test_select_flag():
    args = build_parser().parse_args(["scan", "example.com", "--select"])
    assert args.select is True


def test_enumerate_has_no_ports_or_select_flags():
    args = build_parser().parse_args(["enumerate", "example.com"])
    assert not hasattr(args, "ports")
    assert not hasattr(args, "select")


# --- error paths, driven through cmd_scan itself ---

class _Args:
    """Minimal stand-in for argparse.Namespace, only the fields cmd_scan reads
    before it would need real network access."""

    def __init__(self, **kw):
        self.domain = "example.com"
        self.quiet = True
        self.delay = 0.0
        self.budget = 10
        self.timeout = 1.0
        self.also_scope = None
        self.checks = None
        self.ports = None
        self.select = False
        self.hosts_from = None
        self.no_wayback = True
        self.max_hosts = 1
        self.ip = False
        self.show_discarded = False
        self.json = None
        self.__dict__.update(kw)


def test_unknown_check_name_exits_2(capsys):
    rc = cmd_scan(_Args(checks=["nope"]))
    assert rc == 2
    assert "unknown check" in capsys.readouterr().err


def test_bad_port_spec_exits_2_and_names_the_flag(capsys):
    rc = cmd_scan(_Args(ports="not-a-port"))
    assert rc == 2
    assert "--ports:" in capsys.readouterr().err


def test_backwards_range_via_the_cli_is_reported(capsys):
    rc = cmd_scan(_Args(ports="100-10"))
    assert rc == 2
    err = capsys.readouterr().err
    assert "--ports:" in err
    assert "10-100" in err


def test_ip_table_is_suppressed_when_select_also_shows_one(monkeypatch):
    # --select prints its own host/address table, so the standalone one from
    # -ip must not also fire -- otherwise addresses print twice.
    calls = []
    monkeypatch.setattr(
        "reconfirm.cli.sources.enumerate_hosts",
        lambda *a, **kw: (["a.example.com"], []),
    )
    monkeypatch.setattr("reconfirm.cli.resolves", lambda h: True)
    monkeypatch.setattr("reconfirm.cli.addresses", lambda h: ["1.2.3.4"])
    monkeypatch.setattr("reconfirm.cli._print_addresses", lambda ha: calls.append(ha))
    monkeypatch.setattr(
        "reconfirm.cli.choose_hosts", lambda hosts, addrs, interactive: hosts
    )
    cmd_scan(_Args(checks=["takeover"], ip=True, select=True, hosts_from=None))
    assert calls == []


def test_huge_port_spec_warns_but_does_not_exit(capsys, monkeypatch):
    # Warn-and-continue, not reject: a deliberate full sweep is legitimate,
    # it should just say so. checks is pinned to ["ports"] so this stays a
    # unit test: the default set includes buckets, which queries real S3/GCS
    # endpoints regardless of the (here empty) host list, since it derives
    # candidates from target.domain rather than target.hosts.
    monkeypatch.setattr(
        "reconfirm.cli.sources.enumerate_hosts", lambda *a, **kw: ([], [])
    )
    rc = cmd_scan(_Args(checks=["ports"], ports="1-65535", hosts_from=None))
    err = capsys.readouterr().err
    assert "65535" in err or "this can take a while" in err
    assert rc == 0
