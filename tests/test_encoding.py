"""
Every runtime string in the package must be ASCII.

The Windows console defaults to cp1252. A non-ASCII character in anything that
reaches stdout either raises UnicodeEncodeError or prints as a replacement
character, and both happen *after* the scan has run, which is the expensive
moment to lose results.

test_report.py already asserts the rendered output is ASCII, but it does so
over hand-written sample results, so it only ever proved the samples were
clean. Three em dashes survived that test: one in the CLI's progress line and
one in `inconclusive()`, which builds the reason for every network failure and
is therefore among the most frequently printed strings in the tool.

Walking the AST catches the class rather than the instances. Docstrings are
exempt because they are never printed; prose in a module docstring can use
whatever punctuation reads best.
"""

import ast
import pathlib

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "reconfirm"


def _docstring_nodes(tree):
    """Every string node that serves as a docstring, by identity."""
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            found.add(id(first.value))
    return found


def _non_ascii_literals(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = _docstring_nodes(tree)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in docstrings:
            continue
        bad = sorted({c for c in node.value if ord(c) > 127})
        if bad:
            offenders.append((node.lineno, bad, node.value[:70]))
    return offenders


@pytest.mark.parametrize(
    "path", sorted(PACKAGE.rglob("*.py")), ids=lambda p: p.name
)
def test_runtime_strings_are_ascii(path):
    offenders = _non_ascii_literals(path)
    assert not offenders, "\n".join(
        "line %d: %r in %r" % (line, chars, text) for line, chars, text in offenders
    )


def test_the_walker_actually_finds_things(tmp_path):
    # A test that cannot fail is worse than no test. This pins the walker's
    # behaviour: it flags a real string and ignores a docstring.
    sample = tmp_path / "sample.py"
    sample.write_text(
        '"""A docstring with an em dash — allowed."""\n'
        'MESSAGE = "a runtime string — not allowed"\n',
        encoding="utf-8",
    )
    offenders = _non_ascii_literals(sample)
    assert len(offenders) == 1
    assert offenders[0][0] == 2
