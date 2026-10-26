# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert ThemeAttr to its merged corresponding Curses representation.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses


def themeattr_to_curses_merged(themeattr: ThemeAttr, selected: bool = False) -> int:
    """
    Given a themeattr returns merged curses color + curses attributes.

        Parameters:
            themeattr (ThemeAttr): The ThemeAttr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (int): Curses color | attrs
    """
    curses_col, curses_attrs = themeattr_to_curses(themeattr, selected)
    return curses_col | curses_attrs
