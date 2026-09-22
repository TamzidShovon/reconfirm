"""Parsing the --ports / -p spec string."""

import pytest

from reconfirm.checks.ports import (
    DEFAULT_PORTS,
    MAX_PORT,
    PortSpecError,
    parse_ports,
)


@pytest.mark.parametrize("spec", [None, "", "top", "TOP"])
def test_empty_or_top_gives_the_default_list(spec):
    assert parse_ports(spec) == DEFAULT_PORTS


@pytest.mark.parametrize("spec", ["-", "all", "ALL"])
def test_dash_or_all_gives_every_port(spec):
    result = parse_ports(spec)
    assert result[0] == 1
    assert result[-1] == MAX_PORT
    assert len(result) == MAX_PORT


def test_single_port():
    assert parse_ports("80") == [80]


def test_comma_list_is_sorted_and_deduplicated():
    assert parse_ports("443,80,80") == [80, 443]


def test_inclusive_range():
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_single_element_range():
    assert parse_ports("22-22") == [22]


def test_mixed_list_and_ranges():
    assert parse_ports("22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


def test_overlapping_ranges_deduplicate():
    assert parse_ports("1-5,3-7") == [1, 2, 3, 4, 5, 6, 7]


def test_backwards_range_is_rejected_with_a_helpful_message():
    with pytest.raises(PortSpecError, match=r"5-10"):
        parse_ports("10-5")


@pytest.mark.parametrize("spec", ["abc", "22-abc", "abc-22", "99999", "0", "-1"])
def test_invalid_specs_are_rejected(spec):
    with pytest.raises(PortSpecError):
        parse_ports(spec)


def test_trailing_and_stray_commas_are_tolerated():
    assert parse_ports("80,443,") == [80, 443]
    assert parse_ports(",80,") == [80]


def test_whitespace_is_tolerated():
    assert parse_ports(" 80 , 443 ") == [80, 443]
