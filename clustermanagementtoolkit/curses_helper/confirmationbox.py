# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Show a confirmation box.
"""

import curses
import sys
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr


# pylint: disable-next=too-many-locals
def confirmationbox(stdscr: curses.window, **kwargs: Any) -> bool:
    """
    Show a confirmation box centered around y.

        Parameters:
            stdscr (curses.window): The curses window to operate on
            **kwargs (dict[str, Any]): Keyword arguments
                y (int): the y-coordinate to draw the box at
                     (default: maxy // 2)
                x (int): the x-coordinate for the centre point of the box
                     (default: maxx // 2)
                default (bool): The default value
                title (str): The confirmationbox title (default: "")
        Returns:
            (bool): The response
    """
    maxy, maxx = stdscr.getmaxyx()
    y: int = deep_get(kwargs, DictPath("y"), maxy // 2)
    x: int = deep_get(kwargs, DictPath("x"), maxx // 2)
    default: bool = deep_get(kwargs, DictPath("default"), False)
    title: str = deep_get(kwargs, DictPath("title"), "")

    CursesConfiguration.ignoreinput = False
    retval = default

    default_option = "Y/n" if default else "y/N"
    question = f"Are you sure [{default_option}]: "
    height = 3
    width = 2 + max(len(question), len(title))
    ypos = y - height // 2
    xpos = x - width // 2

    win = curses.newwin(height, width, ypos, xpos)
    col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "boxdrawing"))
    win.attrset(col)
    win.erase()
    win.border()
    win.addstr(0, 1, title, themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))
    win.addstr(1, 1, question.ljust(width - 2),
               themeattr_to_curses_merged(ThemeAttr("windowwidget", "default")))
    win.noutrefresh()
    curses.doupdate()

    while True:
        stdscr.timeout(100)
        c = stdscr.getch()
        if c == 27:  # ESCAPE
            break

        if c == ord("") or c == ord(""):
            curses.endwin()
            sys.exit()

        if c in (curses.KEY_ENTER, 10, 13):
            break

        if c in (ord("y"), ord("Y")):
            retval = True
            break

        if c in (ord("n"), ord("N")):
            retval = False
            break

    del win
    stdscr.touchwin()
    stdscr.noutrefresh()
    curses.doupdate()

    return retval
