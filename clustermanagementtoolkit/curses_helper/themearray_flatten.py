# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Flatten a ThemeArray by substituting references with their ThemeStr representation.
"""

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


def themearray_flatten(themearray: list[ThemeRef | ThemeStr]) -> list[ThemeStr]:
    """
    Replace all ThemeRefs in a ThemeArray with ThemeStr.

        Parameters:
            themearray (ThemeArray): The themearray to flatten
        Returns:
            (ThemeArray): The flattened themearray
        Raises:
            ProgrammingError: themearray is not a themearray
    """
    themearray_flattened = []

    for item in themearray:
        if isinstance(item, ThemeStr):
            themearray_flattened.append(item)
        elif isinstance(item, ThemeRef):
            themearray_flattened += item.to_themearray()
        else:
            errmsg = [
                [("themearray_flatten()", "emphasis"),
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

    return themearray_flattened
