# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Draw a vertical tee line.
"""

import curses

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def window_tee_vline(win: curses.window, x: int,
                     start: int, end: int, formatting: ThemeAttr | None = None) -> None:
    """
    Draw a vertical line with "tees" ("┬", "┴") at the ends.

        Parameters:
            win (curses.window): The curses window to operate on
            x (int): The y-coordinate
            start (int): the starting point of the vline
            end (int): the ending point of the vline
            formatting (ThemeAttr): Optional ThemeAttr to apply to the line
    """
    ttee = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#ttee"))
    btee = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#btee"))
    vline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#vline"))

    if formatting is None:
        formatting = ThemeAttr("main", "default")

    y = start

    addthemearray(win, [ThemeStr(ttee, formatting)], y=y, x=x)

    while y < end:
        y += 1
        addthemearray(win, [ThemeStr(vline, formatting)], y=y, x=x)

    addthemearray(win, [ThemeStr(btee, formatting)], y=end, x=x)
