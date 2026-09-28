"""The mutation catalog must keep describing the code it mutates.

`tests/mutation.py` is the slow check that each authority predicate is defended. This
is the fast one that the catalog itself has not rotted: every edit must still match
exactly once in the file it names, and every file it names must have tests assigned.
A catalog that silently stopped matching would report "no survivors" about nothing.
"""

from __future__ import annotations

import mutation
import pytest


@pytest.mark.parametrize("mutant", mutation.CATALOG, ids=lambda mutant: mutant.name)
def test_every_mutation_still_matches_the_code_exactly_once(mutant):
    text = (mutation.ROOT / mutant.path).read_text(encoding="utf-8")
    assert text.count(mutant.old) == 1
    assert mutant.old != mutant.new


def test_every_mutated_file_has_tests_assigned_and_they_exist():
    for mutant in mutation.CATALOG:
        assert mutant.tests, mutant.path
        for selector in mutant.tests:
            assert (mutation.ROOT / selector).is_file(), selector


def test_the_catalog_names_are_unique():
    names = [mutant.name for mutant in mutation.CATALOG]
    assert len(names) == len(set(names))
