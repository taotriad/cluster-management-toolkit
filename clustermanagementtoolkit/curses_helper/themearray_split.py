# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Split a ThemeArray into substrings.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_split(themearray: list[ThemeStr], separator: str = " ") -> list[list[ThemeStr]]:
    """
    Perform split() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to split
            separator (str): The character to split on
        Returns:
            ([ThemeArray]): An splitted themearray
    """
    themearrays: list[list[ThemeStr]] = []
    tmp_themearray: list[ThemeStr] = []

    # The only easy way to split a themearray string is to iterate over every single segment,
    # then over every single character in the segment and reconstruct the constituent parts
    # until we encounter the separator and then flush.
    for segment in themearray:
        themeattr = segment.get_themeattr()

        for char in str(segment):
            if char == separator:
                themearrays.append(tmp_themearray)
                tmp_themearray = []
                continue
            tmp_themearray.append(ThemeStr(char, themeattr))
    if tmp_themearray:
        themearrays.append(tmp_themearray)

    return themearrays
