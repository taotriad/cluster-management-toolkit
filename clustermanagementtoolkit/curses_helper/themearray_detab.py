# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Replace tabs with spaces.
"""

from clustermanagementtoolkit.curses_helper.themearray_len import themearray_len

from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_detab(themearray: list[ThemeRef | ThemeStr]) -> list[ThemeRef | ThemeStr]:
    """
    Replace all tabs in a ThemeArray with spaces.

        Parameters:
            themearray (ThemeArray): The themearray to detab
        Returns:
            (ThemeArray): The detabbed themearray
        Raises:
            ProgrammingError: themearray is not a themearray
    """
    themearray_detabbed: list[ThemeRef | ThemeStr] = []
    length = 0

    for segment in themearray:
        if isinstance(segment, ThemeRef):
            length += themearray_len([segment])
            themearray_detabbed.append(segment)
        elif isinstance(segment, ThemeStr):
            # We need to replace tabs with spaces; it's not a trivial process and we cannot get it
            # perfect, but we'll do what we can.
            tabsplit = str(segment).split("\t")
            if len(tabsplit) > 1:
                new_string = ""
                tab = ""
                for subsegment in tabsplit:
                    new_string += tab
                    new_string += subsegment
                    tabsize = (length + len(new_string)) % 8
                    if not tabsize:
                        tabsize = 8
                    tab = "".ljust(tabsize)
            else:
                new_string = str(segment)
            # Replace the string component of the ThemeStr()
            segment.string = new_string
            themearray_detabbed.append(segment)
            length += len(new_string)
    return themearray_detabbed
