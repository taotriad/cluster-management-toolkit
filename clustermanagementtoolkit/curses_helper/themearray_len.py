# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the length of a ThemeArray.
"""

from collections.abc import Sequence

from clustermanagementtoolkit.curses_helper.themearray_to_string import themearray_to_string
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_len(themearray: Sequence[ThemeRef | ThemeStr]) -> int:
    """
    Given a themearray return its length.

        Parameters:
            themearray (ThemeArray): A themearray
        Returns:
            (int): The length of the unformatted string
    """
    return len(themearray_to_string(themearray))
