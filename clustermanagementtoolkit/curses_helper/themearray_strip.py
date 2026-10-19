# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Strip a ThemeArray.
"""

from clustermanagementtoolkit.curses_helper.themearray_lstrip import themearray_lstrip
from clustermanagementtoolkit.curses_helper.themearray_rstrip import themearray_rstrip
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def themearray_strip(themearray: list[ThemeStr], characters: str = " ") -> list[ThemeStr]:
    """
    Perform strip() on a ThemeArray.

        Parameters:
            themearray (ThemeArray): The themearray to strip
            characters (str): The characters to strip
        Returns:
            (ThemeArray): An stripped themearray
        Raises:
            AttributeError: [Propagated from ThemeRef] The ThemeArray has not been flattened;
                            it contains ThemeRefs.
    """
    return themearray_lstrip(themearray_rstrip(themearray, characters), characters)
