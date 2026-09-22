"""Interactive host selection.

Shows what enumeration found, then asks which of it to probe. Selections are
cumulative: each answer adds to a queue, so several ranges can be stacked
before the scan starts.

Everything here takes its input and output as arguments rather than touching
sys.stdin directly, so the selection logic is testable without a terminal.
"""

import sys

ALL = ("all", "a", "*")
NONE = ("none", "n", "q", "quit")
DONE = ("done", "d", "go", "run", "")


class SelectionError(ValueError):
    """Raised when a selection string cannot be parsed."""


def parse_selection(text, count):
    """Turn "1,3,5-7" into zero-based indices, validated against count."""
    text = (text or "").strip().lower()
    if not text:
        raise SelectionError("empty selection")
    if text in ALL:
        return list(range(count))

    chosen = []
    for part in text.replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_text, _, hi_text = part.partition("-")
            lo, hi = _index(lo_text, count, part), _index(hi_text, count, part)
            if lo > hi:
                lo, hi = hi, lo
            chosen.extend(range(lo, hi + 1))
        else:
            chosen.append(_index(part, count, part))

    if not chosen:
        raise SelectionError("nothing selected")
    # Preserve the order given, drop repeats.
    seen, ordered = set(), []
    for i in chosen:
        if i not in seen:
            seen.add(i)
            ordered.append(i)
    return ordered


def _index(text, count, context):
    text = text.strip()
    if not text.isdigit():
        raise SelectionError("%r in %r is not a number" % (text, context))
    value = int(text)
    if not 1 <= value <= count:
        raise SelectionError(
            "%d is outside the range 1-%d" % (value, count)
        )
    return value - 1


def format_table(hosts, addresses=None):
    """Render the numbered host list."""
    addresses = addresses or {}
    width = max((len(h) for h in hosts), default=0)
    number_width = len(str(len(hosts)))
    lines = []
    for i, host in enumerate(hosts, 1):
        found = addresses.get(host) or []
        shown = ", ".join(found[:3])
        if len(found) > 3:
            shown += " (+%d more)" % (len(found) - 3)
        lines.append(
            "  %s  %s  %s" % (str(i).rjust(number_width), host.ljust(width), shown or "-")
        )
    return "\n".join(lines)


def choose_hosts(hosts, addresses=None, reader=None, stream=None, interactive=True):
    """Prompt for a selection and return the chosen hosts, in order.

    Returns every host unchanged when there is nothing to choose between, when
    interactive is False, or when input is not a terminal -- a prompt that
    blocks a piped or scripted run is worse than no prompt.
    """
    stream = stream or sys.stderr
    if not hosts:
        return []
    if not interactive:
        return list(hosts)

    if reader is None:
        if not (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
            stream.write(
                "note: input is not a terminal, so all %d hosts were selected\n"
                % len(hosts)
            )
            return list(hosts)
        reader = input

    stream.write("\nHOSTS  (%d found)\n" % len(hosts))
    stream.write("-" * 52 + "\n")
    stream.write(format_table(hosts, addresses) + "\n\n")
    stream.write(
        "Select hosts to scan. Ranges and lists work (1,3,5-7).\n"
        "Selections stack, so answer again to add more.\n"
        "  all   every host        done  start the scan\n"
        "  none  cancel            list  show the table again\n\n"
    )

    queued = []

    def summarise():
        if not queued:
            return "nothing queued"
        return "%d queued: %s" % (
            len(queued), ", ".join(hosts[i] for i in queued[:4])
            + (" ..." if len(queued) > 4 else "")
        )

    while True:
        try:
            answer = reader("reconfirm [%s] > " % summarise()).strip().lower()
        except (EOFError, KeyboardInterrupt):
            stream.write("\ncancelled\n")
            return []

        if answer in NONE:
            return []
        if answer == "list":
            stream.write(format_table(hosts, addresses) + "\n")
            continue
        if answer in DONE:
            if queued:
                return [hosts[i] for i in queued]
            stream.write("nothing queued yet - select some hosts, or 'none' to cancel\n")
            continue

        try:
            picked = parse_selection(answer, len(hosts))
        except SelectionError as e:
            stream.write("  %s\n" % e)
            continue

        added = [i for i in picked if i not in queued]
        queued.extend(added)
        stream.write("  +%d host(s) queued (%d total)\n" % (len(added), len(queued)))
