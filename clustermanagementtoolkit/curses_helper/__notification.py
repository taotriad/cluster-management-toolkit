# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Common helper used by notice dialogs and alert dialogs.
"""

import curses

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501


def __notification(y: int, x: int, message: str, formatting: ThemeAttr) -> curses.window:
    height = 3
    width = 2 + len(message)
    ypos = y - height // 2
    xpos = x - width // 2

    win = curses.newwin(height, width, ypos, xpos)
    col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "boxdrawing"))
    win.attrset(col)
    win.erase()
    win.border()
    win.addstr(1, 1, message, themeattr_to_curses_merged(formatting))
    win.noutrefresh()
    curses.doupdate()
    return win
