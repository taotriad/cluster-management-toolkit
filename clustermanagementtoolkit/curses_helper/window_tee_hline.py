# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Draw a horizontal tee line.
"""

import curses

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def window_tee_hline(win: curses.window, y: int, start: int, end: int,
                     tee: bool = True, formatting: ThemeAttr | None = None) -> None:
    """
    Draw a horizontal line with "tees" ("├", "┤") at the ends.

        Parameters:
            win (curses.window): The curses window to operate on
            y (int): The y-coordinate
            start (int): The starting point of the hline
            end (int): The ending point of the hline
            tee (bool): Should the line include tees at the ends?
            formatting (ThemeAttr): Optional ThemeAttr to apply to the line
    """
    hline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#hline"))
    if tee:
        ltee = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#ltee"))
        rtee = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#rtee"))
    else:
        ltee = hline
        rtee = hline

    if formatting is None:
        formatting = ThemeAttr("main", "default")

    hlinearray: list[ThemeRef | ThemeStr] = [
        ThemeStr(ltee, formatting),
        ThemeStr("".rjust(end - start - 1, hline), formatting),
        ThemeStr(rtee, formatting),
    ]

    addthemearray(win, hlinearray, y=y, x=start)
