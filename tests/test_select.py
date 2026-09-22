"""Interactive host selection: parsing, the table, and the queueing prompt."""

import io

import pytest

from reconfirm.select import (
    SelectionError,
    choose_hosts,
    format_table,
    parse_selection,
)

HOSTS = ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]


# --- parse_selection ---

@pytest.mark.parametrize("text, expected", [
    ("1", [0]),
    ("1,3", [0, 2]),
    ("1-3", [0, 1, 2]),
    ("2-2", [1]),
    ("all", [0, 1, 2, 3]),
    ("*", [0, 1, 2, 3]),
    ("1 3", [0, 2]),
    ("3,1", [2, 0]),
    ("1,1,2", [0, 1]),
])
def test_parse_selection(text, expected):
    assert parse_selection(text, len(HOSTS)) == expected


@pytest.mark.parametrize("text", ["", "0", "5", "abc", "2-1-3", "-", "1-"])
def test_parse_selection_rejects(text):
    with pytest.raises(SelectionError):
        parse_selection(text, len(HOSTS))


def test_reversed_range_is_normalised():
    assert parse_selection("3-1", 4) == [0, 1, 2]


# --- format_table ---

def test_table_numbers_from_one():
    table = format_table(HOSTS)
    assert table.splitlines()[0].strip().startswith("1")


def test_table_shows_addresses_when_given():
    table = format_table(["a.example.com"], {"a.example.com": ["1.2.3.4"]})
    assert "1.2.3.4" in table


def test_table_shows_dash_for_unresolved():
    table = format_table(["a.example.com"], {"a.example.com": []})
    assert "-" in table


def test_table_truncates_many_addresses():
    table = format_table(["a.example.com"], {"a.example.com": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]})
    assert "+1 more" in table


# --- choose_hosts: non-interactive paths ---

def test_no_hosts_returns_empty():
    assert choose_hosts([]) == []


def test_interactive_false_returns_everything_unchanged():
    assert choose_hosts(HOSTS, interactive=False) == HOSTS


def test_non_tty_stdin_selects_everything(monkeypatch):
    class NotATty:
        def isatty(self):
            return False

    monkeypatch.setattr("sys.stdin", NotATty())
    stream = io.StringIO()
    result = choose_hosts(HOSTS, stream=stream)
    assert result == HOSTS
    assert "not a terminal" in stream.getvalue()


# --- choose_hosts: scripted interactive session ---

def _reader(answers):
    it = iter(answers)

    def read(_prompt):
        return next(it)

    return read


def test_single_selection_then_done():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["1", "done"]), stream=stream)
    assert result == ["a.example.com"]


def test_selections_stack_across_turns():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["1", "3", "done"]), stream=stream)
    assert result == ["a.example.com", "c.example.com"]


def test_range_selection():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["1-3", "done"]), stream=stream)
    assert result == HOSTS[:3]


def test_all_still_requires_done():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["all", "done"]), stream=stream)
    assert result == HOSTS


def test_all_does_not_short_circuit_the_prompt():
    # "all" must queue like any other selection, not end the session on its
    # own -- otherwise a later "none" can never take effect.
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["all", "none"]), stream=stream)
    assert result == []


def test_none_cancels():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["1", "none"]), stream=stream)
    assert result == []


def test_empty_answer_means_done():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["2", ""]), stream=stream)
    assert result == ["b.example.com"]


def test_done_with_nothing_queued_reprompts():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["done", "1", "done"]), stream=stream)
    assert result == ["a.example.com"]
    assert "nothing queued yet" in stream.getvalue()


def test_invalid_selection_reprompts_without_crashing():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["9", "1", "done"]), stream=stream)
    assert result == ["a.example.com"]
    assert "outside the range" in stream.getvalue()


def test_list_redisplays_the_table():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["list", "1", "done"]), stream=stream)
    assert result == ["a.example.com"]
    assert stream.getvalue().count("d.example.com") >= 2


def test_duplicate_selection_is_not_queued_twice():
    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=_reader(["1", "1", "done"]), stream=stream)
    assert result == ["a.example.com"]


def test_eof_cancels_cleanly():
    def raises_eof(_prompt):
        raise EOFError

    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=raises_eof, stream=stream)
    assert result == []
    assert "cancelled" in stream.getvalue()


def test_keyboard_interrupt_cancels_cleanly():
    def raises_kbi(_prompt):
        raise KeyboardInterrupt

    stream = io.StringIO()
    result = choose_hosts(HOSTS, reader=raises_kbi, stream=stream)
    assert result == []


def test_output_is_ascii():
    stream = io.StringIO()
    choose_hosts(HOSTS, reader=_reader(["1", "done"]), stream=stream)
    stream.getvalue().encode("ascii")
