# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Left-strip a ThemeArray.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_lstrip(themearray: list[ThemeStr], characters: str = " ") -> list[ThemeStr]:
    """
    Perform lstrip() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to lstrip
            characters (str): The characters to strip
        Returns:
            (ThemeArray): An lstripped themearray
        Raises:
            AttributeError: [Propagated from ThemeRef] The ThemeArray has not been flattened;
                            it contains ThemeRefs.
    """
    new_themearray: list[ThemeStr] = []

    for segment in themearray:
        # Skip completely empty leading elements
        if not new_themearray:
            if not str(segment).strip(characters):
                continue
            new_themearray.append(ThemeStr(str(segment).lstrip(characters),
                                           segment.get_themeattr()))
            continue
        new_themearray.append(segment)
    return new_themearray
