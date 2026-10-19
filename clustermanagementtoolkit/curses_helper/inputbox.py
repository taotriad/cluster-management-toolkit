# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Show an inputbox.
"""

import curses
import curses.textpad
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration
from clustermanagementtoolkit.curses_helper.inputwrapper import inputwrapper
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr


def inputbox(stdscr: curses.window, **kwargs: Any) -> str:
    """
    Show an input box at (y, x).

        Parameters:
            stdscr (curses.window): The curses window to operate on
            **kwargs (dict[str, Any]): Keyword arguments
                y (int): the y-coordinate to draw the box at
                     (default: maxy // 2)
                x (int): the x-coordinate for the left edge of the inputbox
                     (default: 1)
                width (int): the width of the inputbox
                         (default: maxx - 1)
                title (str): The inputbox title (default: "")
        Returns:
            (str): The inputted string
    """
    maxy, maxx = stdscr.getmaxyx()
    y = deep_get(kwargs, DictPath("y"), maxy // 2)
    x = deep_get(kwargs, DictPath("x"), 1)
    width = deep_get(kwargs, DictPath("width"), maxx - 2)
    title = deep_get(kwargs, DictPath("title"), "")

    # Show the cursor; seems some implementations of curses (or terminals?)
    # might not support toggling the cursor; they will throw an exception instead.
    # Catch this and pretend that everything is fine.
    try:
        curses.curs_set(True)
    except curses.error:
        pass

    CursesConfiguration.ignoreinput = False

    win = curses.newwin(3, width, y, x)
    col, _discard = themeattr_to_curses(ThemeAttr("windowwidget", "boxdrawing"))
    win.attrset(col)
    win.erase()
    win.border()
    if title:
        win.addstr(0, 1, title, themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))
    win.noutrefresh()

    inputarea = win.subwin(1, width - 2, y + 1, x + 1)
    inputarea.bkgd(" ", themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))
    inputarea.attrset(themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))
    inputarea.noutrefresh()

    tpad = curses.textpad.Textbox(inputarea)
    curses.doupdate()

    tpad.edit(inputwrapper)

    if CursesConfiguration.ignoreinput:
        string = ""
    else:
        string = tpad.gather()

    del tpad
    del win

    # Hide the cursor; seems some implementations of curses (or terminals?)
    # might not support toggling the cursor; they will throw an exception instead.
    # Catch this and pretend that everything is fine.
    try:
        curses.curs_set(False)
    except curses.error:
        pass
    stdscr.touchwin()
    stdscr.noutrefresh()
    curses.doupdate()

    return string.rstrip()
