# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for special strings, such as <none>, <default>, <unset>, etc.
"""

from clustermanagementtoolkit.cmttypes import StatusGroup

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import color_status_group


def format_special(string: str, selected: bool) -> ThemeRef | ThemeStr | None:
    """
    Given a string, substitute any special strings with their formatted version.

        Parameters:
            string (str): The string to format
            selected (bool): Is the string selected?
        Returns:
            (ThemeRef | ThemeStr): A ThemeStr
    """
    formatted_string: ThemeRef | ThemeStr | None = None

    if string in ("<none>", "<unknown>"):
        fmt = ThemeAttr("types", "none")
        formatted_string = ThemeStr(string, fmt, selected)
    elif string in ("<undefined>", "<unspecified>"):
        fmt = ThemeAttr("types", "undefined")
        formatted_string = ThemeStr(string, fmt, selected)
    elif string in ("<empty>", "<unset>"):
        fmt = ThemeAttr("types", "unset")
        formatted_string = ThemeStr(string, fmt, selected)
    elif string == "<not ready>":
        fmt = color_status_group(StatusGroup.NOT_OK)
        formatted_string = ThemeStr(string, fmt, selected)

    return formatted_string
