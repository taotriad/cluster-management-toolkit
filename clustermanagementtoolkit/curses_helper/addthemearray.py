# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Add a ThemeArray to a Curses window.
"""

import curses
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themestring_to_cursestuple import themestring_to_cursestuple  # noqa: E501


def addthemearray(win: curses.window,
                  array: list[ThemeRef | ThemeStr], **kwargs: Any) -> tuple[int, int]:
    """
    Add a ThemeArray to a curses window.

        Parameters:
            win (curses.window): The curses window to operate on
            array ([ThemeRef|ThemeStr]): The themearray to add to the curses window
            **kwargs (dict[str, Any]): Keyword arguments
                y (int): The y-coordinate (-1 to start from current cursor position)
                x (int): The x-coordinate (-1 to start from current cursor position)
                deleted (bool): Should the theme be overridden as deleted?
        Returns:
            (int, int):
                (int): The new y-coordinate
                (int): The new x-coordinate
    """
    y: int = deep_get(kwargs, DictPath("y"), -1)
    x: int = deep_get(kwargs, DictPath("x"), -1)
    deleted: bool = deep_get(kwargs, DictPath("deleted"), False)

    for item in themearray_flatten(array):
        if deleted:
            item.set_themeattr(ThemeAttr("types", "deleted"))
        string, attr = themestring_to_cursestuple(item)
        # If there still are remaining <NUL> occurences, replace them
        string = string.replace("\x00", "<NUL>")
        try:
            win.addstr(y, x, string, attr)
        except curses.error:
            pass
        y, x = win.getyx()
    return y, x
