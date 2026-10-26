# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert a ThemeArray into an unformatted string.
"""

from collections.abc import Sequence

from clustermanagementtoolkit.curses_helper.themestr import ThemeArray
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


# This extracts the string without formatting;
# once everything uses proper ThemeArray this wo not be necessary anymore
def themearray_to_string(themearray: Sequence[ThemeRef | ThemeStr]) -> str:
    """
    Given a themearray return an unformatted string.

        Parameters:
            themearray (ThemeArray): A themearray
        Returns:
            (str): The unformatted string
    """
    string = ""

    if isinstance(themearray, ThemeArray):
        return str(themearray)

    for fragment in themearray:
        string += str(fragment)

    return string
