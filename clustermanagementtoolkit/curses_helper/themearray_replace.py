# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Search for a character in a ThemeArray and replace it with another character.
"""

from collections.abc import Sequence

from clustermanagementtoolkit.curses_helper.themearray_compact import themearray_compact
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_replace(themearray: Sequence[ThemeRef | ThemeStr],
                       oldvalue: str, newvalue: str, count: int = -1) -> list[ThemeStr]:
    """
    Search and replace for needle in haystack.
    Note: Currently only single character replace is supported.

        Parameters:
            themearray (ThemeArray): The themearray to substitute characters in
            oldvalue (str): The character search for
            newvalue (str): The character to replace with
        Returns:
            (ThemeArray): The modified themearray
    """
    new_themearray: list[ThemeRef | ThemeStr] = []

    for segment in themearray:
        if isinstance(segment, ThemeRef):
            new_themearray.append(segment)
            continue

        themeattr = segment.themeattr
        for char in str(segment):
            if count and char == oldvalue:
                char = newvalue
                count -= 1
            new_themearray.append(ThemeStr(char, themeattr))

    return themearray_compact(new_themearray)
