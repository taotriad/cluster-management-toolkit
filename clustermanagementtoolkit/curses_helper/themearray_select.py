# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Mark a ThemeArray as (un)selected.
"""

from collections.abc import Sequence

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


def themearray_select(themearray: Sequence[ThemeRef | ThemeStr],
                      selected: bool = False,
                      force: bool = False) -> Sequence[ThemeRef | ThemeStr]:
    """
    Iterate through the themearray and set all selected fields that are currently None.

        Parameters:
            themearray (ThemeArray): The themearray to select/unselect
            selected (bool): True is selected, False otherwise
            force (bool): True to set selected=selected even if item.seleected isn't None
        Returns:
            (ThemeArray): The (un)seleected themearray
        Raises:
            ProgrammingError: themearray is not a themearray
    """
    themearray_selected: list[ThemeRef | ThemeStr] = []

    for item in themearray:
        if not isinstance(item, (ThemeRef, ThemeStr)):
            errmsg = [
                [("themearray_select_none()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("item = ", "default"),
                 (f"{item}", "argument"),
                 (" (type: ", "default"),
                 (f"{type(item)}", "argument"),
                 (", expected: ", "default"),
                 ("ThemeRef", "argument"),
                 (" or ", "default"),
                 ("ThemeStr", "argument"),
                 (")", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   facility=str(ThemeStrConfiguration.themefile),
                                   formatted_msg=formatted_msg)

        if item.selected is None or force:
            item.selected = selected
        themearray_selected.append(item)

    return themearray_selected
