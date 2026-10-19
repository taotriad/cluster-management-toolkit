# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Draw a horizontal scroll bar.
"""

import curses

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


# pylint: disable-next=too-many-arguments,too-many-locals,too-many-positional-arguments
def scrollbar_horizontal(win: curses.window, y: int, minx: int, maxx: int,
                         width: int, xoffset: int, clear_color: ThemeAttr) \
        -> tuple[tuple[int, int], tuple[int, int], tuple[int, int, int]]:
    """
    Draw a horizontal scroll bar.

        Parameters:
            win (curses.window): The curses window to operate on
            y (int): The y-coordinate
            minx (int): the starting point of the scroll bar
            maxx (int): the ending point of the scroll bar
            width (int): the width of the scrollable area (number of columns)
            xoffset (int): the offset into the scrollable area
            clear_color (ThemeAttr): The theme attr to use if the scrollbar is disabled
        Returns:
            ((int, int), (int, int), (int, int)):
                (int, int): (y, x) for left arrow
                (int, int): (y, x) for right arrow
                (int, int): (y, x) for midpoint of dragger
    """
    arrowleft = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#arrowleft"), "▲")
    arrowright = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#arrowright"), "▼")
    scrollbar = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#scrollbar"), "▒")
    horizontaldragger_left = deep_get(ThemeStrConfiguration.theme,
                                      DictPath("boxdrawing#horizontaldragger_left"), "█")
    horizontaldragger_midpoint = deep_get(ThemeStrConfiguration.theme,
                                          DictPath("boxdrawing#horizontaldragger_midpoint"), "◉")
    horizontaldragger_right = deep_get(ThemeStrConfiguration.theme,
                                       DictPath("boxdrawing#horizontaldragger_right"), "█")
    hline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#hline"))

    leftarrow = (-1, -1)
    rightarrow = (-1, -1)
    hdragger = (-1, -1, -1)

    maxoffset = width - (maxx - minx) - 1

    scrollbararray: list[ThemeRef | ThemeStr] = []

    # We only need a scrollbar if we can actually scroll
    if maxoffset > 0:
        scrollbararray += [
            ThemeStr(arrowleft, ThemeAttr("main", "scrollbar_arrows")),
        ]
        leftarrow = (y, minx)

        scrollbararray += [
            ThemeStr("".rjust(maxx - minx - 1, scrollbar), ThemeAttr("main", "scrollbar")),
        ]
        scrollbararray += [
            ThemeStr(arrowright, ThemeAttr("main", "scrollbar_arrows")),
        ]
        rightarrow = (y, maxx)

        curpos = minx + 1 + int((maxx - minx) * (xoffset / (maxoffset)))
        curpos = min(curpos, maxx - 5)

        addthemearray(win, scrollbararray, y=y, x=minx)

        draggerarray: list[ThemeRef | ThemeStr] = [
            ThemeStr(f"{horizontaldragger_left}{horizontaldragger_left}",
                     ThemeAttr("main", "dragger")),
            ThemeStr(f"{horizontaldragger_midpoint}",
                     ThemeAttr("main", "dragger_midpoint")),
            ThemeStr(f"{horizontaldragger_right}{horizontaldragger_right}",
                     ThemeAttr("main", "dragger")),
        ]

        addthemearray(win, draggerarray, y=y, x=curpos)
        hdragger = (y, curpos, 5)
    # But we might need to cover up the lack of one if the window has been resized
    else:
        scrollbararray += [
            ThemeStr("".rjust(maxx - minx + 1, hline), clear_color),
        ]
        addthemearray(win, scrollbararray, y=y, x=minx)

    # (y, x Upper arrow), (y, x Lower arrow), (y, x, len horizontal dragger)
    return leftarrow, rightarrow, hdragger
