"""Command line entry point.

`enumerate` reads third-party archives and touches nothing belonging to the
target. `scan` enumerates and then probes, so it carries the flags that
bound that traffic.
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__, checks, report, sources
from .checks import Target
from .checks import ports as ports_check
from .confidence import CONFIRMED, tally
from .net import Scope, Session, addresses, resolves
from .select import choose_hosts

# Lookups are I/O bound and independent, and a dead name can sit on a
# resolver timeout for over a second.
_RESOLVER_WORKERS = 16


def _print_addresses(host_addresses):
    by_address = {}
    for host, found in host_addresses.items():
        by_address.setdefault(",".join(found) or "-", []).append(host)

    print("\nADDRESSES  (%d hosts on %d distinct address sets)"
          % (len(host_addresses), len(by_address)))
    print("-" * 52)
    for address, names in sorted(by_address.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print("  %s" % address)
        for name in sorted(names):
            print("      %s" % name)
    # Progress goes to stderr unbuffered; without this flush the table lands
    # after the run it was meant to precede whenever stdout is a pipe.
    print(flush=True)


def _partition_by_resolution(hosts):
    with ThreadPoolExecutor(max_workers=_RESOLVER_WORKERS) as pool:
        flags = list(pool.map(resolves, hosts))
    live = [h for h, ok in zip(hosts, flags) if ok]
    dead = [h for h, ok in zip(hosts, flags) if not ok]
    return live, dead


def _emitter(quiet):
    if quiet:
        return lambda _msg: None
    def emit(msg):
        print(msg, file=sys.stderr, flush=True)
    return emit


def _build_session(args, domain):
    scope = Scope([domain] + list(args.also_scope or []))
    return Session(
        scope,
        min_interval=args.delay,
        per_host_budget=args.budget,
        timeout=args.timeout,
    )


def cmd_enumerate(args):
    emit = _emitter(args.quiet)
    session = _build_session(args, args.domain)
    hosts, notes = sources.enumerate_hosts(
        session, args.domain, use_wayback=not args.no_wayback, emit=emit
    )

    if args.ip:
        emit("resolving %d hostnames" % len(hosts))
        width = max((len(h) for h in hosts), default=0)
        for host in hosts:
            found = addresses(host)
            # Tab-separated so it still pipes into cut and awk.
            print("%s\t%s" % (host.ljust(width), ",".join(found) if found else "-"))
    else:
        for host in hosts:
            print(host)

    for note in notes:
        print("note: %s" % note, file=sys.stderr)
    emit("%d unique hostnames" % len(hosts))
    return 0


def _requested_checks(explicit, ports_spec):
    """Which check names a scan should run.

    -p on its own means a port scan and nothing else. Adding it to the default
    set instead would turn "scan these ports" into a full recon sweep, which
    on one live run meant probing third-party storage endpoints nobody asked
    about. Pair it with --checks to run both.
    """
    if explicit:
        requested = list(explicit)
        if ports_spec is not None and ports_check.NAME not in requested:
            requested.append(ports_check.NAME)
        return requested
    if ports_spec is not None:
        return [ports_check.NAME]
    return list(checks.DEFAULT_CHECKS)


def cmd_scan(args):
    emit = _emitter(args.quiet)
    session = _build_session(args, args.domain)

    requested = _requested_checks(args.checks, args.ports)

    try:
        modules = checks.get(requested)
    except KeyError as e:
        # str() on a KeyError reprs its argument, so the message would print
        # wrapped in quotes.
        print(e.args[0], file=sys.stderr)
        return 2

    port_list = None
    if args.ports is not None:
        try:
            port_list = ports_check.parse_ports(args.ports)
        except ports_check.PortSpecError as e:
            print("--ports: %s" % e, file=sys.stderr)
            return 2
        if len(port_list) > ports_check.SPEC_WARN_THRESHOLD:
            print(
                "note: --ports %r selects %d ports; this can take a while"
                % (args.ports, len(port_list)),
                file=sys.stderr,
            )

    if args.hosts_from:
        # utf-8-sig, not utf-8: Notepad and PowerShell's Out-File write a
        # BOM, which plain utf-8 keeps, silently losing the first hostname.
        # A no-op on files without one.
        with open(args.hosts_from, encoding="utf-8-sig") as fh:
            hosts = [line.strip() for line in fh if line.strip()]
        notes = []
        emit("%d hostnames read from %s" % (len(hosts), args.hosts_from))
    else:
        hosts, notes = sources.enumerate_hosts(
            session, args.domain, use_wayback=not args.no_wayback, emit=emit
        )

    hosts = [h for h in hosts if h in session.scope]

    # Resolve before truncating, so --max-hosts spends its budget on hosts
    # that exist rather than on whatever sorts first.
    if hosts:
        emit("resolving %d hostnames" % len(hosts))
        live, dead = _partition_by_resolution(hosts)
        if dead:
            notes.append(
                "%d of %d enumerated names do not resolve and were not probed"
                % (len(dead), len(hosts))
            )
        hosts = live

    if args.max_hosts and len(hosts) > args.max_hosts:
        notes.append(
            "probed %d of %d live hostnames (--max-hosts); the rest were not "
            "tested and are absent from these results rather than clear"
            % (args.max_hosts, len(hosts))
        )
        hosts = hosts[:args.max_hosts]

    # Resolved either way once --select needs it to show addresses in the
    # table; cached by the earlier partition, so this costs only formatting.
    host_addresses = {h: addresses(h) for h in hosts} if (args.ip or args.select) else {}
    # --select prints its own host/address table right before prompting, so
    # this one is skipped rather than shown twice.
    if args.ip and not args.select:
        _print_addresses(host_addresses)

    if args.select:
        before = len(hosts)
        hosts = choose_hosts(hosts, host_addresses, interactive=True)
        if not hosts:
            print("no hosts selected, nothing to do", file=sys.stderr)
            return 0
        if len(hosts) < before:
            notes.append(
                "%d of %d enumerated hosts were selected interactively" % (len(hosts), before)
            )
        host_addresses = {h: host_addresses[h] for h in hosts if h in host_addresses}

    target = Target(domain=args.domain, hosts=hosts)
    emit("probing %d hosts with %d check(s), %.1fs between requests"
         % (len(hosts), len(modules), args.delay))

    if not hosts:
        # Even the seeded apex was filtered out. Say so, rather than let an
        # empty result set read as a clean one.
        notes.append(
            "no hosts were probed, so these results say nothing about the target -- "
            "check the domain and whether the passive sources returned anything"
        )

    results = []
    for module in modules:
        emit("running %s - %s" % (module.NAME, module.DESCRIPTION))
        kwargs = ({"ports": port_list, "polite": args.polite}
                  if module is ports_check else {})
        results.extend(module.run(session, target, emit=emit, **kwargs))

    report.render(
        results,
        show_discarded=args.show_discarded,
        notes=notes,
    )

    if args.json:
        path = report.write_json(
            args.json, results, args.domain,
            notes=notes, requests_made=session.requests_made(),
            addresses=host_addresses,
        )
        print("wrote %s" % path, file=sys.stderr)

    # Exit 1 on a confirmed result so this composes with shell conditionals
    # and CI steps. Unverified does not trip it.
    return 1 if tally(results)[CONFIRMED] else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reconfirm",
        description="Attack-surface recon that grades its own findings.",
        epilog="Only run this against domains you are authorised to test.",
    )
    parser.add_argument("--version", action="version", version="reconfirm " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def shared(p):
        p.add_argument("domain", help="registrable domain, e.g. example.com")
        p.add_argument("--delay", type=float, default=0.3, metavar="SECONDS",
                       help="minimum gap between requests (default: 0.3)")
        p.add_argument("--budget", type=int, default=200, metavar="N",
                       help="maximum requests per host (default: 200)")
        p.add_argument("--timeout", type=float, default=8.0, metavar="SECONDS",
                       help="per-request timeout (default: 8)")
        p.add_argument("--also-scope", nargs="*", metavar="DOMAIN",
                       help="additional domains this run is authorised to touch")
        p.add_argument("--no-wayback", action="store_true",
                       help="skip the Wayback Machine source")
        p.add_argument("-q", "--quiet", action="store_true",
                       help="suppress progress output on stderr")
        # Both spellings: -ip is what people type, --ip is conventional.
        p.add_argument("-ip", "--ip", dest="ip", action="store_true",
                       help="resolve hosts and show their IP addresses")

    p_enum = sub.add_parser("enumerate", help="list hostnames from passive sources only")
    shared(p_enum)
    p_enum.set_defaults(func=cmd_enumerate)

    p_scan = sub.add_parser("scan", help="enumerate, then probe and grade")
    shared(p_scan)
    p_scan.add_argument("--checks", nargs="*", metavar="NAME",
                        help="checks to run (default: %s; also available: %s)"
                             % (", ".join(checks.DEFAULT_CHECKS),
                                ", ".join(sorted(set(checks.CHECKS) - set(checks.DEFAULT_CHECKS)))))
    p_scan.add_argument("--hosts-from", metavar="FILE",
                        help="read hostnames from a file instead of enumerating")
    p_scan.add_argument("--max-hosts", type=int, default=50, metavar="N",
                        help="probe at most N hostnames (default: 50; 0 for no limit)")
    p_scan.add_argument("--show-discarded", action="store_true",
                        help="include claims the tool ruled out, and why")
    p_scan.add_argument("--json", metavar="FILE", help="also write results as JSON")
    p_scan.add_argument("-p", "--ports", metavar="SPEC", default=None,
                        help="port(s) to scan, e.g. '80,443', '1-1024', 'all' "
                             "(default: %d common ports). On its own this runs "
                             "the ports check and nothing else; add --checks to "
                             "run others alongside it"
                             % len(ports_check.DEFAULT_PORTS))
    p_scan.add_argument("--select", action="store_true",
                        help="show the enumerated hosts and choose which to "
                             "probe interactively, before scanning")
    p_scan.add_argument("--polite", action="store_true",
                        help="have the ports check honor --delay and "
                             "--timeout instead of connecting as fast as "
                             "possible (slower, gentler on fragile hosts)")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
