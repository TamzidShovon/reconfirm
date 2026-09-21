"""
Command line entry point.

Two subcommands, matching the passive/active split the package is built
around. `enumerate` reads third-party archives and touches nothing belonging
to the target. `scan` enumerates and then probes, which is traffic the target
can see and log — so it takes the flags that bound that traffic, and prints
what it is about to do before it does it.
"""

import argparse
import sys

from . import __version__, checks, report, sources
from .checks import Target
from .confidence import CONFIRMED, tally
from .net import Scope, Session


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
    for host in hosts:
        print(host)
    for note in notes:
        print("note: %s" % note, file=sys.stderr)
    emit("%d unique hostnames" % len(hosts))
    return 0


def cmd_scan(args):
    emit = _emitter(args.quiet)
    session = _build_session(args, args.domain)

    try:
        modules = checks.get(args.checks) if args.checks else list(checks.CHECKS.values())
    except KeyError as e:
        # str() on a KeyError reprs its argument, so the message would print
        # wrapped in quotes.
        print(e.args[0], file=sys.stderr)
        return 2

    if args.hosts_from:
        with open(args.hosts_from, encoding="utf-8") as fh:
            hosts = [line.strip() for line in fh if line.strip()]
        notes = []
        emit("%d hostnames read from %s" % (len(hosts), args.hosts_from))
    else:
        hosts, notes = sources.enumerate_hosts(
            session, args.domain, use_wayback=not args.no_wayback, emit=emit
        )

    hosts = [h for h in hosts if h in session.scope]
    if args.max_hosts:
        if len(hosts) > args.max_hosts:
            notes.append(
                "probed the first %d of %d hostnames (--max-hosts); the rest were "
                "not tested and are absent from these results rather than clear"
                % (args.max_hosts, len(hosts))
            )
        hosts = hosts[:args.max_hosts]

    target = Target(domain=args.domain, hosts=hosts)
    emit("probing %d hosts with %d check(s), %.1fs between requests"
         % (len(hosts), len(modules), args.delay))

    results = []
    for module in modules:
        emit("running %s - %s" % (module.NAME, module.DESCRIPTION))
        results.extend(module.run(session, target, emit=emit))

    report.render(
        results,
        show_discarded=args.show_discarded,
        notes=notes,
    )

    if args.json:
        path = report.write_json(
            args.json, results, args.domain,
            notes=notes, requests_made=session.requests_made(),
        )
        print("wrote %s" % path, file=sys.stderr)

    # Exit 1 when something was confirmed, so the tool composes with shell
    # conditionals and CI steps. Unverified results deliberately do not trip
    # it: an inconclusive check is not a finding.
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

    p_enum = sub.add_parser("enumerate", help="list hostnames from passive sources only")
    shared(p_enum)
    p_enum.set_defaults(func=cmd_enumerate)

    p_scan = sub.add_parser("scan", help="enumerate, then probe and grade")
    shared(p_scan)
    p_scan.add_argument("--checks", nargs="*", metavar="NAME",
                        help="checks to run (default: all): "
                             + ", ".join(sorted(checks.CHECKS)))
    p_scan.add_argument("--hosts-from", metavar="FILE",
                        help="read hostnames from a file instead of enumerating")
    p_scan.add_argument("--max-hosts", type=int, default=50, metavar="N",
                        help="probe at most N hostnames (default: 50; 0 for no limit)")
    p_scan.add_argument("--show-discarded", action="store_true",
                        help="include claims the tool ruled out, and why")
    p_scan.add_argument("--json", metavar="FILE", help="also write results as JSON")
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
