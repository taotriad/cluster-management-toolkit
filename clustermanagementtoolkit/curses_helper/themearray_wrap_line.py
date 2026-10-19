# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Split a themearray into multiple ThemeArrays, each maxwidth long.
"""

from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_wrap_line(themearray: list[ThemeRef | ThemeStr], maxwidth: int = -1,
                         wrap_marker: bool = True) -> list[list[ThemeRef | ThemeStr]]:
    """
    Given a themearray, split it into multiple lines, each maxwidth long.

        Parameters:
            themearray (ThemeArray): The themearray to wrap
            maxwidth (int): The maximum number of characters before wrapping
            wrap_marker (bool): Should the line end in a wrap marker?
        Returns:
            ([ThemeArray]): A list of themearrays
    """
    if maxwidth == -1:
        return [themearray]

    if not (themearray_flat := themearray_flatten(themearray)):
        return []

    linebreak = ThemeRef("separators", "line_break").to_themearray()

    if wrap_marker:
        linebreaklen = len(linebreak)
    else:
        linebreaklen = 0

    themearrays: list[list[ThemeRef | ThemeStr]] = []
    tmp_themearray: list[ThemeRef | ThemeStr] = []
    tmplen = 0
    i = 0

    while True:
        # Does the fragment fit?
        tfilen = len(themearray_flat[i])
        if tmplen + tfilen < maxwidth:
            tmp_themearray.append(themearray_flat[i])
            tmplen += tfilen
            i += 1
        # Nope
        else:
            string = str(themearray_flat[i])
            themeattr = themearray_flat[i].get_themeattr()

            tmp_themearray.append(ThemeStr(string[:maxwidth - linebreaklen - tmplen], themeattr))
            if wrap_marker:
                tmp_themearray += linebreak
            themearray_flat[i] = ThemeStr(string[maxwidth - linebreaklen - tmplen:], themeattr)
            themearrays.append(tmp_themearray)
            tmp_themearray = []
            tmplen = 0
            continue
        if i == len(themearray_flat):
            themearrays.append(tmp_themearray)
            break

    return themearrays
