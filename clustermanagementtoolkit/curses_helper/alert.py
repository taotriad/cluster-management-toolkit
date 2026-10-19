# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Show an alert dialog.
"""

import curses
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.__notification import __notification
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr


def alert(stdscr: curses.window | None, message: str, **kwargs: Any) -> curses.window | None:
    """
    Show an alert.

        Parameters:
            stdscr (curses.window): The curses window to operate on
            message (str): The message to show
            **kwargs (dict[str, Any]): Keyword arguments
                y (int): the y-coordinate of the window centre point (default: maxy // 2)
                x (int): the x-coordinate of the window centre point (default: maxx // 2)
                wait_for_keypress (bool): Wait for keypress before returning?
        Returns:
            (curses.window): A reference to the notification window
    """
    wait_for_keypress: bool = deep_get(kwargs, DictPath("wait_for_keypress"), False)
    tmp_y: int = deep_get(kwargs, DictPath("y"))
    tmp_x: int = deep_get(kwargs, DictPath("x"))
    if stdscr:
        maxy, maxx = stdscr.getmaxyx()
        if not tmp_y:
            tmp_y = maxy // 2
        if not tmp_x:
            tmp_x = maxx // 2
    elif not tmp_y or not tmp_x:
        raise ProgrammingError("When using notice() without stdscr passing y & x is mandatory")

    y = tmp_y
    x = tmp_x

    win: curses.window | None = \
        __notification(y, x, message, ThemeAttr("windowwidget", "alert"))
    if stdscr and wait_for_keypress:
        while True:
            stdscr.timeout(100)
            c = stdscr.getch()
            if c != -1:
                del win
                win = None
                break
    return win
