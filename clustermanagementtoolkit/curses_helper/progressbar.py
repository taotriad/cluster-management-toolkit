# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Show a progress bar.
"""

import curses
import errno
import sys

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr, ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def progressbar(win: curses.window | None, y: int, minx: int, maxx: int,
                progress: int, title: str | None = None) -> curses.window:
    """
    A progress bar.
    Usage: Initialise by calling with a reference to a variable set to None
    Pass in progress in 0-100; once done clean up with:
    stdscr.touchwin()
    stdscr.refresh()

        Parameters:
            win (curses.window): The curses window to operate on
            y (int): the y-coordinate
            miny (int): the starting point of the progress bar
            maxy (int): the ending point of the progress bar
            progress (int): 0-100%
            title (str): The title for the progress bar (None for an anonymous window)
        Returns:
            (curses.window): A reference to the progress bar window
    """
    if not (isinstance(y, int) and isinstance(minx, int)
            and isinstance(maxx, int) and isinstance(progress, int)
            and (title is None or isinstance(title, str))):
        errmsg = [
            [("curses_helper.progressbar()", "emphasis"),
             (" initialised with invalid argument(s):", "error")],
            [("y = ", "default"),
             (f"{y}", "argument"),
             (" (type: ", "default"),
             (f"{type(y)}", "argument"),
             (", expected: ", "default"),
             ("int", "argument"),
             (")", "default")],
            [("minx = ", "default"),
             (f"{minx}", "argument"),
             (" (type: ", "default"),
             (f"{type(minx)}", "argument"),
             (", expected: ", "default"),
             ("int", "argument"),
             (")", "default")],
            [("maxx = ", "default"),
             (f"{maxx}", "argument"),
             (" (type: ", "default"),
             (f"{type(maxx)}", "argument"),
             (", expected: ", "default"),
             ("int", "argument"),
             (")", "default")],
            [("progress = ", "default"),
             (f"{progress}", "argument"),
             (" (type: ", "default"),
             (f"{type(progress)}", "argument"),
             (", expected: ", "default"),
             ("int", "argument"),
             (")", "default")],
            [("title = ", "default"),
             (f"{title}", "argument"),
             (" (type: ", "default"),
             (f"{type(title)}", "argument"),
             (", expected: ", "default"),
             ("str or None", "argument"),
             (")", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        raise ProgrammingError(unformatted_msg,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    width = maxx - minx + 1

    if progress < 0:
        errmsg = [
            [("curses_helper.progressbar()", "emphasis"),
             (" called with progress < 0:", "error")],
            [("progress = ", "default"),
             (f"{progress}", "argument")],
            [("Negative progress is not supported; this is not a regression bar.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        raise ProgrammingError(unformatted_msg,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)
    if progress > 100:
        errmsg = [
            [("curses_helper.progressbar()", "emphasis"),
             (" called with progress > 100:", "error")],
            [("progress = ", "default"),
             (f"{progress}", "argument")],
            [("That's impossible. No one can give more than 100%. "
              + "By definition, that is the most anyone can give.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        raise ProgrammingError(unformatted_msg,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    if win is None:
        win = curses.newwin(3, width, y, minx)
        col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "boxdrawing"))
        win.attrset(col)
        win.erase()
        win.border()
        col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "default"))
        win.bkgd(" ", col)
        if title is not None:
            win.addstr(0, 1, title, themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))

    # progress is in % of the total length
    solidblock = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#solidblock"))
    dimmedblock = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#dimmedblock"))
    for x in range(width - 2):
        try:
            if x < (width * progress) // 100:
                addthemearray(win, [ThemeStr(solidblock, ThemeAttr("main", "progressbar"))],
                              y=1, x=x + 1)
            else:
                addthemearray(win, [ThemeStr(dimmedblock, ThemeAttr("main", "progressbar"))],
                              y=1, x=x + 1)
        except curses.error:
            curses.endwin()
            ansithemeprint([ANSIThemeStr("Critical", "critical"),
                            ANSIThemeStr(": Live resizing progressbar() is currently broken; "
                                         "this is a known issue.", "default")], stderr=True)
            sys.exit(errno.ENOTSUP)

    win.noutrefresh()
    curses.doupdate()

    return win
