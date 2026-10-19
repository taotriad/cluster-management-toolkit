# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Flatten a ThemeArray, then compact it by merging substrings with the same formatting.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten


def themearray_compact(themearray: list[ThemeRef | ThemeStr]) -> list[ThemeStr]:
    """
    Replace all ThemeRefs in a ThemeArray with ThemeStr,
    then merge all strings with the same formatting.

        Parameters:
            themearray (ThemeArray): The themearray to flatten
        Returns:
            (ThemeArray): The flattened themearray
        Raises:
            ProgrammingError: themearray is not a themearray
    """
    themearray_flattened: list[ThemeStr] = themearray_flatten(themearray)
    new_themearray = []
    latest_str = ""
    latest_attr = None

    for segment in themearray_flattened:
        string = str(segment)
        themeattr = segment.get_themeattr()
        if latest_attr == themeattr:
            latest_str += string
            continue

        if latest_str and latest_attr:
            new_themearray.append(ThemeStr(latest_str, latest_attr))

        latest_str = string
        latest_attr = themeattr

    if latest_str and latest_attr:
        new_themearray.append(ThemeStr(latest_str, latest_attr))

    return new_themearray
