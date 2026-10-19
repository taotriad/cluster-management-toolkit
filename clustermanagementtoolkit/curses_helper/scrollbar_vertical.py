# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Draw a vertical scroll bar.
"""

import curses

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


# pylint: disable-next=too-many-arguments,too-many-locals,too-many-positional-arguments
def scrollbar_vertical(win: curses.window, x: int, miny: int, maxy: int,
                       height: int, yoffset: int, clear_color: ThemeAttr) \
        -> tuple[tuple[int, int], tuple[int, int], tuple[int, int, int]]:
    """
    Draw a vertical scroll bar.

        Parameters:
            win (curses.window): The curses window to operate on
            x (int): The x-coordinate
            miny (int): the starting point of the scroll bar
            maxy (int): the ending point of the scroll bar
            height (int): the height of the scrollable area (number of rows)
            yoffset (int): the offset into the scrollable area
            clear_color (ThemeAttr): The theme attr to use if the scrollbar is disabled
        Returns:
            ((int, int), (int, int), (int, int)):
                (int, int): (y, x) for upper arrow
                (int, int): (y, x) for lower arrow
                (int, int): (y, x) for midpoint of dragger
    """
    arrowup = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#arrowup"), "▲")
    arrowdown = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#arrowdown"), "▼")
    scrollbar = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#scrollbar"), "▒")
    verticaldragger_upper = deep_get(ThemeStrConfiguration.theme,
                                     DictPath("boxdrawing#verticaldragger_upper"), "█")
    verticaldragger_midpoint = deep_get(ThemeStrConfiguration.theme,
                                        DictPath("boxdrawing#verticaldragger_midpoint"), "◉")
    verticaldragger_lower = deep_get(ThemeStrConfiguration.theme,
                                     DictPath("boxdrawing#verticaldragger_lower"), "█")
    vline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#vline"))
    upperarrow = (-1, -1)
    lowerarrow = (-1, -1)
    vdragger = (-1, -1, -1)

    maxoffset = height - (maxy - miny) - 1

    # We only need a scrollbar if we can actually scroll
    if maxoffset > 0:
        addthemearray(win, [ThemeStr(arrowup,
                                     ThemeAttr("main", "scrollbar_arrows"))], y=miny, x=x)
        upperarrow = (miny, x)
        y = miny + 1
        while y < maxy:
            addthemearray(win, [ThemeStr(scrollbar, ThemeAttr("main", "scrollbar"))], y=y, x=x)
            y += 1
        addthemearray(win, [ThemeStr(arrowdown,
                                     ThemeAttr("main", "scrollbar_arrows"))], y=maxy, x=x)
        lowerarrow = (maxy, x)
        curpos = miny + 1 + int((maxy - miny) * (yoffset / (maxoffset)))
        curpos = min(curpos, maxy - 3)
        vdragger = (curpos, x, 3)
        addthemearray(win, [ThemeStr(verticaldragger_upper,
                                     ThemeAttr("main", "dragger"))], y=curpos + 0, x=x)
        addthemearray(win, [ThemeStr(verticaldragger_midpoint,
                                     ThemeAttr("main", "dragger_midpoint"))], y=curpos + 1, x=x)
        addthemearray(win, [ThemeStr(verticaldragger_lower,
                                     ThemeAttr("main", "dragger"))], y=curpos + 2, x=x)
    # But we might need to cover up the lack of one if the window has been resized
    else:
        for y in range(miny, maxy + 1):
            addthemearray(win, [ThemeStr(vline, clear_color)], y=y, x=x)

    # (y, x Upper arrow), (y, x Lower arrow), (y, x, len vertical dragger)
    return upperarrow, lowerarrow, vdragger
