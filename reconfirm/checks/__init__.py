"""The check contract and the registry of available checks.

A check receives a Target and the shared Session and returns Results. It
does not print, rank severity, or write files.

Adding one means writing a module with NAME, DESCRIPTION and run(), then
listing it in CHECKS below.
"""

from dataclasses import dataclass, field

from . import buckets, ports, secrets, takeover


@dataclass
class Target:
    domain: str
    hosts: list = field(default_factory=list)
    """`domain` is the registrable domain the run was authorised against;
    `hosts` are the hostnames enumeration produced."""


CHECKS = {
    module.NAME: module
    for module in (takeover, secrets, buckets, ports)
}

# What a bare `scan` runs. `ports` is registered but excluded: it opens
# connections to ports a browser would not, so it is opt-in via --checks.
DEFAULT_CHECKS = ("takeover", "secrets", "buckets")


def get(names):
    """Resolve check names to modules, raising on an unknown name."""
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise KeyError(
            "unknown check(s): %s (available: %s)"
            % (", ".join(unknown), ", ".join(sorted(CHECKS)))
        )
    return [CHECKS[n] for n in names]
