# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Class and helpers for a curses-based user interface.
"""

# pylint: disable=too-many-lines

from collections.abc import Callable
import copy
import curses
from datetime import datetime, timedelta, UTC
import errno
from operator import itemgetter
import re
import sys
from typing import Any, cast, ClassVar, NoReturn

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import clamp
from clustermanagementtoolkit.cmtlib import none_timestamp
from clustermanagementtoolkit.cmtlib import seconds_to_age

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import Retval
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.addthemearray import addthemearray
from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration
from clustermanagementtoolkit.curses_helper.format_helptext import format_helptext
from clustermanagementtoolkit.curses_helper.get_labels import get_labels
from clustermanagementtoolkit.curses_helper.inputbox import inputbox
from clustermanagementtoolkit.curses_helper.get_mousemask import get_mousemask
from clustermanagementtoolkit.curses_helper.scrollbar_horizontal import scrollbar_horizontal
from clustermanagementtoolkit.curses_helper.scrollbar_vertical import scrollbar_vertical
from clustermanagementtoolkit.curses_helper.set_mousemask import set_mousemask
from clustermanagementtoolkit.curses_helper.themearray_to_string import themearray_to_string
from clustermanagementtoolkit.curses_helper.themearray_flatten import themearray_flatten
from clustermanagementtoolkit.curses_helper.themearray_len import themearray_len
from clustermanagementtoolkit.curses_helper.themeattr_to_curses import themeattr_to_curses
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themeattr_to_curses_merged import themeattr_to_curses_merged  # noqa: E501
from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.curses_helper.themestring_to_cursestuple import themestring_to_cursestuple  # noqa: E501
from clustermanagementtoolkit.curses_helper.curses_helper_types import WidgetLineAttrs
from clustermanagementtoolkit.curses_helper.window_tee_hline import window_tee_hline
from clustermanagementtoolkit.curses_helper.window_tee_vline import window_tee_vline


def move_cur_with_offset(curypos: int, yoffset: int,
                         maxcurypos: int, maxyoffset: int,
                         movement: int, **kwargs: Any) -> tuple[int, int]:
    """
    Calculate a new cursor position based on an offset.

        Parameters:
            curypos (int): The current cursor on the screen
            yoffset (int): The offset in the range
            maxcurypos (int): The maximum cursor screen position
            maxyoffset (int): The maximum offset in the range
            movement (int): The movement to make
            **kwargs (dict[str, Any]): Keyword arguments
                wraparound (bool): Should the list wraparound (default: False)
        Returns:
            (int, int):
                (int): The new cursor position
                (int): The new offset in the range
    """
    wraparound: bool = deep_get(kwargs, DictPath("wraparound"), False)

    newcurypos = curypos + movement
    newyoffset = yoffset

    # If we are being asked to move forward but we are already
    # at the end of the list, it is prudent not to move,
    # even if the caller so requests.
    # It is just good manners, really; likewise if we are being asked to move
    # backward past the start of the list.
    #
    # One may gracefully accept the request if so instructed using the wraparound flag, though.
    if movement > 0:
        if newcurypos > maxcurypos:
            if newyoffset == maxyoffset and wraparound:
                newcurypos = 0
                newyoffset = 0
            else:
                newcurypos = maxcurypos
                newyoffset = min(yoffset + movement - (maxcurypos - curypos), maxyoffset)
    elif movement < 0 and newcurypos < 0:
        if (yoffset + curypos) + newcurypos < 0 and wraparound:
            newcurypos = maxcurypos
            newyoffset = maxyoffset
        else:
            newcurypos = 0
            newyoffset = max(yoffset + movement + curypos, 0)
    return newcurypos, newyoffset


def __move_xoffset(**kwargs: Any) -> tuple[Retval, dict]:
    maxxoffset: int = deep_get(kwargs, DictPath("maxxoffset"))
    xoffset: int = deep_get(kwargs, DictPath("xoffset"))
    offset: int = deep_get(kwargs, DictPath("offset"))
    return Retval.MATCH, {"xoffset": clamp(xoffset + offset, 0, maxxoffset)}


def __move_cur_with_offset(**kwargs: Any) -> tuple[Retval, dict]:
    curypos: int = deep_get(kwargs, DictPath("curypos"))
    yoffset: int = deep_get(kwargs, DictPath("yoffset"))
    maxcurypos: int = deep_get(kwargs, DictPath("maxcurypos"))
    maxyoffset: int = deep_get(kwargs, DictPath("maxyoffset"))
    offset: int = deep_get(kwargs, DictPath("offset"))
    curypos, yoffset = move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, offset)
    return Retval.MATCH, {"curypos": curypos, "yoffset": yoffset}


windowwidget_shortcuts = {
    # The windowwidget is special;
    # it doesn't have helptexts, etc.
    "__common_shortcuts": [],
    "Scroll one row up": {
        "helptext": ("[Up]", "Scroll one row up"),
        "shortcut": [curses.KEY_UP],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": -1,
        },
    },
    "Scroll one row down": {
        "helptext": ("[Down]", "Scroll one row down"),
        "shortcut": [curses.KEY_DOWN],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": 1,
        },
    },
    "Scroll one character left": {
        "helptext": ("[Left]", "Scroll one character left"),
        "shortcut": [curses.KEY_LEFT],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_xoffset,
        "action_args": {
            "offset": -1,
        },
    },
    "Scroll one character right": {
        "helptext": ("[Right]", "Scroll one character right"),
        "shortcut": [curses.KEY_RIGHT],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_xoffset,
        "action_args": {
            "offset": 1,
        },
    },
    "Scroll 10 lines up": {
        "helptext": ("[Page Up]", "Scroll 10 lines up"),
        "shortcut": [curses.KEY_PPAGE],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": -10,
        },
    },
    "Scroll 10 lines down": {
        "helptext": ("[Page Down]", "Scroll 10 lines down"),
        "shortcut": [curses.KEY_NPAGE],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": 10,
        },
    },
    "Jump to first row": {
        "helptext": ("[Shift] + [Home]", "Jump to first row"),
        "shortcut": [curses.KEY_SHOME],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": -sys.maxsize,
        },
    },
    "Jump to last row": {
        "helptext": ("[Shift] + [End]", "Jump to last row"),
        "shortcut": [curses.KEY_SEND],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_cur_with_offset,
        "action_args": {
            "offset": sys.maxsize,
        },
    },
    "Jump to beginning of row": {
        "helptext": ("[Home]", "Jump to beginning of row"),
        "shortcut": [curses.KEY_HOME],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_xoffset,
        "action_args": {
            "offset": -sys.maxsize,
        },
    },
    "Jump to end of row": {
        "helptext": ("[End]", "Jump to end of row"),
        "shortcut": [curses.KEY_END],
        "helpgroup": 3,
        "action": "key_callback",
        "action_call": __move_xoffset,
        "action_args": {
            "offset": sys.maxsize,
        },
    },
}


# A generic window widget
# items is a list of tuples, like so:
# (widgetlineattr, strarray, strarray, ...)
# A strarray is a list of tuples, where every tuple is of the format (string, attribute)
# Alternatively items can be a list of dicts
# on the format:
# {
#    "lineattrs": ...,
#    "columns": strarray, ...,
#    "retval": the value to return if this item is selected (any type is allowed)
# }
# noqa: E501 pylint: disable-next=too-many-arguments,too-many-locals,too-many-statements,too-many-branches,too-many-positional-arguments
def windowwidget(stdscr: curses.window, maxy: int, maxx: int, y: int, x: int,
                 items: list[dict[str, Any]], **kwargs: Any) -> Any:
    """
    A generic:ish scrollable window widget with support for one or multiple columns,
    with or without selectable elements.

        Parameters:
            stdscr (curses.window): The parent window
            maxy (int): the max y-position of the window widget
            maxx (int): the max x-position of the window widget
            y (int): The y-centrepoint of the window widget
            x (int): The x-centrepoint of the window widget
            items ([dict]): The data to populate the window widget with
            **kwargs (dict[str, Any]): Keyword arguments
                headers ((str, ...)): The headers for the columns
                title (str): The title of the window
                preselection (str|set): The pre-selected entry/entries
                cursor (bool): Show a cursor; True/False?
                taggable (bool): Should the items be taggable?
                key_f6 (bool): Should [F6] to toggle categorised list entries be
                               a keyboard option?
        Returns:
            (set|(int, bool|int|str|None), bool|int|str|None):
                (set): A set of tagged items
                ---
                (int, bool|int|str|None):
                    (int): Confirm value
                    (bool|int|str|None): Selected entry or None if no selection was made
                ---
                (bool|int|str|None): Selected entry or None if no selection was made
    """
    headers: tuple[str, ...] = deep_get(kwargs, DictPath("headers"))
    title: str = deep_get(kwargs, DictPath("title"), "")
    preselection: str | set[int] = deep_get(kwargs, DictPath("preselection"), "")
    cursor: bool = deep_get(kwargs, DictPath("cursor"), True)
    taggable: bool = deep_get(kwargs, DictPath("taggable"), False)
    key_f6: bool = deep_get(kwargs, DictPath("KEY_F6"), False)

    stdscr.refresh()
    CursesConfiguration.ignoreinput = False

    padwidth = 2
    listpadheight = len(items)

    if not isinstance(items, list) or not items:
        errmsg = [
            [("windowwidget()", "emphasis"),
             (" called with invalid argument(s):", "error")],
            [("items = ", "default"),
             (f"{items}", "argument"),
             (" (type:", "default"),
             (f"{type(items)}", "argument"),
             (", expected: ", "default"),
             (f"{list}", "argument"),
             (" with at least one element)", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise TypeError(unformatted_msg)

    if not isinstance(items[0], dict):
        errmsg = [
            [("windowwidget()", "emphasis"),
             (" called with invalid argument(s):", "error")],
            [("items = ", "default"),
             (f"{items[0]}", "argument"),
             (" (type:", "default"),
             (f"{type(items[0])}", "argument"),
             (", expected: ", "default"),
             (f"{dict}", "argument"),
             (")", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise TypeError(unformatted_msg)

    columns = len(items[0]["columns"])
    lengths = [0] * columns

    if headers is not None:
        if len(headers) != columns:
            raise ValueError("Mismatch: Number of headers passed to windowwidget "
                             f"({len(headers)}) does not match number of columns ({columns})")

        for i in range(columns):
            lengths[i] = len(headers[i])

    tagprefix = str(ThemeRef("separators", "tag"))

    # Leave room for a tag prefix column if needed
    if taggable:
        tagprefixlen = len(tagprefix)
    else:
        tagprefixlen = 0

    # Every item is a line
    for item in items:
        for i in range(columns):
            length = themearray_len(item["columns"][i])
            lengths[i] = max(lengths[i], length)

    listpadwidth = 0
    for i in range(columns):
        if i > 0:
            listpadwidth += padwidth
        listpadwidth += lengths[i]

    if len(title) > listpadwidth:
        lengths[columns - 1] += len(title) - listpadwidth

    listpadwidth = max(listpadwidth, len(title)) + tagprefixlen

    extra_height = 0

    if headers is not None:
        extra_height += 2

    height = min(maxy - 5, listpadheight) + 2 + extra_height
    maxcurypos = min(height - 3 - extra_height, listpadheight - 1)
    maxyoffset = listpadheight - (height - 2 - extra_height)
    width = min(maxx - 5, listpadwidth) + 2

    xoffset = 0
    maxxoffset = listpadwidth - (width - 2)

    yoffset = 0

    ypos = y - height // 2
    xpos = x - width // 2

    if headers is not None:
        headerpadypos = ypos + 1
        listpadypos = ypos + 3
        scrollbarypos = 3
    else:
        listpadypos = ypos + 1
        scrollbarypos = 1

    win = curses.newwin(height, width, ypos, xpos)
    col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "boxdrawing"))
    win.attrset(col)
    win.erase()
    win.border()
    col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "default"))
    win.bkgd(" ", col)
    win.addstr(0, 1, title, themeattr_to_curses_merged(ThemeAttr("windowwidget", "title")))
    listpad = curses.newpad(listpadheight + 1, listpadwidth + 1)
    col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "default"))
    listpad.bkgd(" ", col)

    if headers is not None:
        headerpad = curses.newpad(1, listpadwidth + 1)
        col, __discard = themeattr_to_curses(ThemeAttr("windowwidget", "header"))
        headerpad.bkgd(" ", col)

    selection: int | str | None = None
    curypos = 0

    headerarray: list[ThemeRef | ThemeStr] = []

    # Generate headers
    if headers is not None:
        if taggable:
            headerarray.append(ThemeStr(f"{tagprefix}", ThemeAttr("windowwidget", "highlight")))
        for i in range(columns):
            extrapad = padwidth
            if i == columns - 1:
                extrapad = 0
            headerarray.append(ThemeStr((headers[i].ljust(lengths[i] + extrapad)),
                                        ThemeAttr("windowwidget", "header")))

    # Move to preselection
    if isinstance(preselection, str):
        if preselection != "":
            for y_, item in enumerate(items):
                if isinstance(item["columns"][0][0], ThemeStr):
                    tmp_selection = str(item["columns"][0][0])
                else:
                    tmp_selection = item["columns"][0][0][0]

                if "retval" in item and item["retval"] == preselection \
                        or "retval" not in item and tmp_selection == preselection:
                    curypos, yoffset = move_cur_with_offset(0, yoffset, maxcurypos, maxyoffset, y_)
                    break
        ww_tagged_items = set()
    elif isinstance(preselection, set):
        ww_tagged_items = preselection.copy()
    else:
        raise TypeError("is_taggable() == True, "
                        f"but type(preselection) == {type(preselection)} (must be str or set())")

    uip = UIProps(stdscr)

    # pylint: disable-next=too-many-nested-blocks
    while selection is None:
        for y_, item in enumerate(items):
            if cursor:
                # These parentheses helps readability
                # pylint: disable-next=superfluous-parens
                selected_ = (yoffset + curypos == y_)
            else:
                selected_ = False

            lineattributes = item["lineattrs"]
            linearray: list[ThemeRef | ThemeStr] = []

            if taggable:
                if y_ in ww_tagged_items:
                    linearray.append(ThemeStr(f"{tagprefix}", ThemeAttr("windowwidget", "tag")))
                else:
                    linearray.append(ThemeStr("".ljust(tagprefixlen),
                                              ThemeAttr("windowwidget", "tag")))

            for _x, column in enumerate(item["columns"]):
                themearray: list[ThemeRef | ThemeStr] = []
                length = 0

                for string in column:
                    if isinstance(string, ThemeStr):
                        tmpstring = str(string)
                        attribute = string.themeattr
                    elif isinstance(string, ThemeRef):
                        raise ProgrammingError("FIXME: windowwidget() "
                                               "currently cannot handle ThemeRef")
                    else:
                        raise ProgrammingError("In windowwidget(); "
                                               f"we want to get rid of this: items={items}")
                        # tmpstring = string[0]
                        # attribute = string[1]
                    strlen = len(tmpstring)
                    length += strlen

                    if lineattributes & (WidgetLineAttrs.INVALID) != 0:
                        attribute = ThemeAttr("windowwidget", "alert")
                        themearray.append(ThemeStr(tmpstring, attribute, selected_))
                    elif lineattributes \
                            & (WidgetLineAttrs.DISABLED | WidgetLineAttrs.UNSELECTABLE) != 0:
                        attribute = ThemeAttr("windowwidget", "dim")
                        themearray.append(ThemeStr(tmpstring, attribute, selected_))
                    elif lineattributes & WidgetLineAttrs.SEPARATOR != 0:
                        if attribute == ThemeAttr("windowwidget", "default"):
                            attribute = ThemeAttr("windowwidget", "highlight")
                        tpad = listpadwidth - strlen
                        lpad = int(tpad / 2)
                        rpad = tpad - lpad
                        lpadstr = "".ljust(lpad, "─")
                        rpadstr = "".rjust(rpad, "─")

                        themearray.append(ThemeStr(lpadstr,
                                                   ThemeAttr("windowwidget", "highlight"),
                                          selected_))
                        themearray.append(ThemeStr(tmpstring, attribute, selected_))
                        themearray.append(ThemeStr(rpadstr,
                                                   ThemeAttr("windowwidget", "highlight"),
                                          selected_))
                    else:
                        themearray.append(ThemeStr(tmpstring, attribute, selected_))

                if lineattributes & WidgetLineAttrs.SEPARATOR == 0:
                    padstring = "".ljust(lengths[_x] - length + padwidth)
                    themearray.append(ThemeStr(padstring, attribute, selected_))

                linearray += themearray

            addthemearray(listpad, linearray, y=y_, x=0)

        _upperarrow, _lowerarrow, _vdragger = \
            scrollbar_vertical(win, width - 1, scrollbarypos, height - 2, listpadheight, yoffset,
                               ThemeAttr("windowwidget", "boxdrawing"))
        _leftarrow, _rightarrow, _hdragger = \
            scrollbar_horizontal(win, height - 1, 1, width - 2, listpadwidth, xoffset,
                                 ThemeAttr("windowwidget", "boxdrawing"))

        if headers is not None:
            addthemearray(headerpad, headerarray, y=0, x=0)
            headerxoffset = 0
            if headers:
                headerxoffset = xoffset
            headerpad.noutrefresh(0, headerxoffset,
                                  headerpadypos, xpos + 1, headerpadypos, xpos + width - 2)
            window_tee_hline(win, 2, 0, width - 1,
                             formatting=ThemeAttr("windowwidget", "boxdrawing"))

        listpad.noutrefresh(yoffset, xoffset, listpadypos,
                            xpos + 1, ypos + height - 2, xpos + width - 2)

        win.noutrefresh()
        curses.doupdate()

        oldcurypos = curypos
        oldyoffset = yoffset

        input_args = {
            "curypos": curypos,
            "yoffset": yoffset,
            "maxcurypos": maxcurypos,
            "maxyoffset": maxyoffset,
            "xoffset": xoffset,
            "maxxoffset": maxxoffset,
        }

        retval, return_args = uip.generic_inputhandler(windowwidget_shortcuts, **input_args)
        if retval == Retval.MATCH:
            curypos = deep_get(return_args, DictPath("curypos"), curypos)
            yoffset = deep_get(return_args, DictPath("yoffset"), yoffset)
            xoffset = deep_get(return_args, DictPath("xoffset"), xoffset)

        c: int = int(deep_get(return_args, DictPath("keypress"), -1))

        # The following inputs terminate the loop
        if c == curses.KEY_RESIZE:
            curses.endwin()
            ansithemeprint([ANSIThemeStr("Critical", "critical"),
                            ANSIThemeStr(": Live resizing windowwidget() is currently broken; "
                                         "this is a known issue.", "default")], stderr=True)
            sys.exit(errno.ENOTSUP)
        if c == 27:  # ESCAPE
            selection = ""
            break
        if key_f6 and c == curses.KEY_F6:
            # This is used to toggle categorised list on/off
            selection = -c
            break
        if c in (curses.KEY_ENTER, 10, 13) \
                and items[yoffset + curypos]["lineattrs"] & (WidgetLineAttrs.UNSELECTABLE) == 0:
            if deep_get(items[yoffset + curypos], DictPath("retval")) is None:
                selection = items[yoffset + curypos]["columns"]
            else:
                selection = items[yoffset + curypos]["retval"]
            break

        # While all of these are just navigation
        if taggable and c == ord(" "):
            if curypos + yoffset in ww_tagged_items:
                ww_tagged_items.discard(curypos + yoffset)
            else:
                ww_tagged_items.add(curypos + yoffset)
        elif ord("a") <= c <= ord("z") and cursor:
            # Find the next entry starting with the pressed letter;
            # wrap around if the bottom is hit stop if oldycurypos + oldyoffset is hit
            while True:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset,
                                         maxcurypos, maxyoffset, +1, wraparound=True)
                lineattributes = items[yoffset + curypos]["lineattrs"]
                tmp_char = str(items[yoffset + curypos]["columns"][0][0])[0]
                if tmp_char.lower() == chr(c).lower() \
                        and lineattributes & WidgetLineAttrs.DISABLED == 0:
                    break
                if (curypos + yoffset) == (oldcurypos + oldyoffset):
                    # While we are at the same position in the list
                    # we might not be at the same offsets
                    curypos = oldcurypos
                    yoffset = oldyoffset
                    break
        elif ord("A") <= c <= ord("Z") and cursor:
            # Find the previous entry starting with the pressed letter;
            # wrap around if the top is hit stop if oldycurypos + oldyoffset is hit
            while True:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset,
                                         maxcurypos, maxyoffset, -1, wraparound=True)
                lineattributes = items[yoffset + curypos]["lineattrs"]
                tmp_char = str(items[yoffset + curypos]["columns"][0][0])[0]
                if tmp_char.lower() == chr(c).lower() \
                        and lineattributes & WidgetLineAttrs.DISABLED == 0:
                    break
                if (curypos + yoffset) == (oldcurypos + oldyoffset):
                    # While we are at the same position in the list
                    # we might not be at the same offsets
                    curypos = oldcurypos
                    yoffset = oldyoffset
                    break
        elif c == ord("\t") and cursor:
            # Find next group
            while items[yoffset + curypos]["lineattrs"] & WidgetLineAttrs.SEPARATOR == 0:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, +1)
                if (curypos + yoffset) == (maxcurypos + maxyoffset):
                    break
                # OK, we found a group, now find the first not-group
            while items[yoffset + curypos]["lineattrs"] & WidgetLineAttrs.SEPARATOR != 0:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, +1)
                if (curypos + yoffset) == (maxcurypos + maxyoffset):
                    break
        elif c == curses.KEY_BTAB and cursor:
            # Find previous group
            while items[yoffset + curypos]["lineattrs"] & WidgetLineAttrs.SEPARATOR == 0:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, -1)
                if (curypos + yoffset) == 0:
                    break
            # OK, we found a group, now find the previous not-group
            while items[yoffset + curypos]["lineattrs"] & WidgetLineAttrs.SEPARATOR != 0:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, -1)
                if (curypos + yoffset) == 0:
                    break
            # Finally find the first entry in that group
            while (curypos + yoffset) > 0 \
                    and items[yoffset + curypos]["lineattrs"] & WidgetLineAttrs.SEPARATOR != 0:
                curypos, yoffset = \
                    move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, -1)
                if (curypos + yoffset) == 0:
                    break

        # These only apply if we use a cursor
        if cursor:
            # Find the last acceptable line
            if (yoffset + curypos) == (maxcurypos + maxyoffset):
                while items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    curypos, yoffset = move_cur_with_offset(curypos, yoffset,
                                                            maxcurypos, maxyoffset, -1)
            # We tried moving backwards; do we need to go farther?
            if (yoffset + curypos) > (oldyoffset + oldcurypos):
                while (yoffset + curypos) < len(items) \
                        and items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    curypos, yoffset = \
                        move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, +1)
                if (yoffset + curypos) == len(items) \
                        and items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    yoffset = oldyoffset
                    curypos = oldcurypos
            # Find the first acceptable line
            elif (yoffset + curypos) == 0:
                while items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    curypos, yoffset = \
                        move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, +1)
            # We tried moving backwards; do we need to go farther?
            elif (yoffset + curypos) < (oldyoffset + oldcurypos):
                while (yoffset + curypos) \
                        and items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    curypos, yoffset = \
                        move_cur_with_offset(curypos, yoffset, maxcurypos, maxyoffset, -1)
                if (yoffset + curypos) == 0 \
                        and items[yoffset + curypos]["lineattrs"] \
                        & (WidgetLineAttrs.SEPARATOR | WidgetLineAttrs.DISABLED) != 0:
                    curypos = oldcurypos + oldyoffset
                    yoffset = 0

        if not cursor:
            yoffset += curypos
            yoffset = min(maxyoffset, yoffset)
            curypos = 0

    del listpad
    del win

    if taggable:
        return ww_tagged_items

    return selection


# pylint: disable-next=too-many-instance-attributes,too-many-public-methods
class UIProps:
    """
    The class used for the UI.
    """
    # pylint: disable-next=too-many-statements
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr: curses.window = stdscr

        # Helptext
        self.helptext: list[dict[str, Any]] | None = None

        self.update_forced: bool = False

        # The UID of the selected object (if applicable)
        self.selected_uid = None

        # Remember position by UID (if False we remember by cursor position)
        self.remember_uid: bool = True

        # The timestamp
        self.last_timestamp_update: str | None = None

        self.idle_timeout: int = 5
        self.last_action: datetime = datetime.now(UTC)

        # Info to use for populating lists, etc.
        self.sorted_list: list[dict] = []
        self.sortorder_reverse: bool = False

        # Used for searching
        self.searchkey: str = ""

        # Used for label list
        self.labels: list[dict[str, Any]] = []

        # Used for annotation list
        self.annotations: list[dict[str, Any]] = []

        self.miny: int = 0
        self.maxy: int = 0
        self.minx: int = 0
        self.maxx: int = 0
        self.linelen: int = -1
        self.mincurypos: int = 0
        self.maxcurypos: int = 0
        self.curypos: int = 0
        self.yoffset: int = 0
        self.xoffset: int = 0
        self.maxyoffset: int = 0
        self.maxxoffset: int = 0
        self.last_update: datetime = none_timestamp()
        # Number of seconds between updates
        self.update_delay: int = 0
        # Has an update been requested?
        self.update_triggered: bool = False
        # Update will update the content to display,
        # Refresh just updates the display
        self.refresh: bool = True
        self.sortcolumn: str = ""
        self.sortkey1: str = ""
        self.sortkey2: str = ""
        self.field_dict: dict = {}

        self.helpstring: str = "[F1] / [Shift] + H: Help"
        # Should there be a timestamp in the upper right corner?
        self.timestamp: bool = True

        self.selected: dict | None = None

        # For generic information
        self.infopadminwidth: int = 0
        self.infopadypos: int = 0
        self.infopadxpos: int = 0
        self.infopadheight: int = 0
        self.infopadwidth: int = 0
        self.infopad: curses.window | None = None
        # For lists
        self.headerpadminwidth: int = 0
        self.headerpadypos: int = 0
        self.headerpadxpos: int = 0
        self.headerpadheight: int = 0
        self.headerpadwidth: int = 0
        self.headerpad: curses.window | None = None
        self.listlen: int = 0
        # This one really is a misnomer and could possible be confused with the infopad
        self.sort_triggered: bool = False
        self.regenerate_list: bool = False
        self.info: list[dict] = []
        # This is a list of the xoffset for all headers in listviews
        self.tabstops: list[int] = []
        self.listpadypos: int = 0
        self.listpadxpos: int = 0
        self.listpadheight: int = 0
        self.listpadwidth: int = 0
        self.listpad: curses.window | None = None
        self.listpadminwidth: int = 0
        self.reversible: bool = True
        self.sortable: bool = True
        # For logs with a timestamp column
        self.tspadypos: int = 0
        self.tspadxpos: int = 0
        self.tspadheight: int = 0
        self.tspadwidth = len("YYYY-MM-DD HH:MM:SS")
        self.tspad: curses.window | None = None
        self.logpadypos: int = 0
        self.logpadxpos: int = 0
        self.logpadheight: int = 0
        self.logpadwidth: int = 0
        self.logpad: curses.window | None = None
        self.loglen: int = 0
        self.logpadminwidth: int = 0
        self.top_statusbar: curses.window | None = None
        self.bottom_statusbar: curses.window | None = None
        self.top_statusbarypos: int = 0
        self.bottom_statusbarypos: int = 0
        self.continuous_log: bool = False
        self.match_index: int | None = None
        self.search_matches: set[int] = set()
        self.timestamps: list[datetime] = []
        self.facilities: list[tuple[list[ThemeRef | ThemeStr], str] | str] = []
        self.severities: list[LogLevel] = []
        self.messages: list[list[ThemeRef | ThemeStr] | str] = []
        # For checking clicks/drags of the scrollbars
        self.leftarrow: tuple[int, int] = -1, -1
        self.rightarrow: tuple[int, int] = -1, -1
        self.hdragger: tuple[int, int, int] = -1, -1, -1
        self.upperarrow: tuple[int, int] = -1, -1
        self.lowerarrow: tuple[int, int] = -1, -1
        self.vdragger: tuple[int, int, int] = -1, -1, -1

        # Function handler for <enter> / <double-click>
        self.activatedfun: Callable | None = None
        self.on_activation: dict[str, Any] = {}
        self.extraref: str | None = None
        self.data: bool | None = None

        self.windowheader: str = ""
        self.view: tuple[str, str] | str | None = ""

    def __del__(self) -> None:
        if self.infopad:
            del self.infopad
        if self.listpad:
            del self.listpad
        if self.headerpad:
            del self.headerpad
        if self.logpad:
            del self.logpad

    def reselect_uid(self) -> None:
        """
        After the list has been resorted use this to find the correct position again,
        if possible.
        """
        pos = self.curypos + self.yoffset
        if len(self.sorted_list) > pos:
            try:
                self.selected_uid = deep_get(self.sorted_list[pos], DictPath("__uid"))
            except (AttributeError, IndexError):
                self.selected_uid = None

    def update_sorted_list(self) -> None:
        """
        Resort the list.
        """
        if self.curypos == -1 or self.yoffset == -1:
            self.curypos = 0
            self.yoffset = 0

        if not self.sort_triggered:
            return
        self.sort_triggered = False
        self.list_needs_regeneration(True)

        sortkey1, sortkey2 = self.get_sortkeys()
        try:
            self.sorted_list = natsorted(self.info,
                                         key=itemgetter(sortkey1, sortkey2),
                                         reverse=self.sortorder_reverse)
        except TypeError:
            # We could not sort the list; we just keep the current sort order
            self.sorted_list = self.info

        pos = self.curypos + self.yoffset

        # If self.remember_uid is set we (try to) follow the item;
        # else we remain at the cursor position (if possible)
        if self.remember_uid:
            for y, item in enumerate(self.sorted_list):
                uid = None
                try:
                    uid = deep_get(item, DictPath("__uid"))
                except AttributeError:
                    pass
                # If the first element lacks "__uid" all elements will lack it
                if uid is None:
                    break
                if self.selected_uid is None and y == pos:
                    self.selected_uid = uid
                if uid == self.selected_uid:
                    self.move_cur_with_offset(y - pos)

    def update_info(self, info: list[dict]) -> None:
        """
        Update the information for the processed list.

            Parameters:
                ([Info]): The new information
        """
        self.info = info
        self.listlen = len(self.info)
        self.sort_triggered = True

    def update_log_info(self,
                        timestamps: list[datetime],
                        facilities: list[tuple[list[ThemeRef | ThemeStr], str] | str],
                        severities: list[LogLevel],
                        messages: list[list[ThemeRef | ThemeStr] | str]) -> None:
        """
        Update the information for the parsed container log.

            Parameters:
                timestamps ([datetime]): The timestamps
                facilities ([([ThemeRef | ThemeStr], str) | str]): The severities
                severities ([LogLevel]): The LogLevels
                messages ([str | ThemeArray]): The log messages
        """
        self.timestamps = timestamps
        self.facilities = facilities
        self.severities = severities
        self.messages = messages
        self.loglen = len(self.messages)

    def set_update_delay(self, delay: int) -> None:
        """
        Set the update delay.

            Parameters:
                delay (int): The delay between updates in seconds
        """
        self.update_delay = delay
        if delay > 0:
            self.last_update = datetime.now(UTC)

    def force_update(self) -> None:
        """
        Force trigger an update.
        """
        self.update_triggered = True
        self.refresh = True
        self.sort_triggered = True
        self.list_needs_regeneration(True)

    def force_refresh(self) -> None:
        """
        Force trigger a refresh.
        """
        self.list_needs_regeneration(True)
        self.refresh_all()
        self.refresh_window()
        self.update_window()

    def disable_update(self) -> None:
        """
        Disable automated updates.
        """
        self.last_update = none_timestamp()

    def reset_update_delay(self) -> None:
        """
        Reset the update delay.
        """
        if self.update_delay > 0:
            self.last_update = datetime.now(UTC)

    def is_update_triggered(self) -> bool:
        """
        Check whether an update has been triggered.
        if self.update_triggered: either forcibly
        or through the update timeout.

            Returns:
                (bool): True if an update has been triggered
        """
        if self.update_triggered:
            self.update_triggered = False
            return True

        if self.last_update == none_timestamp() or self.update_delay == 0:
            return False

        timediff = datetime.now(UTC) - self.last_update
        duration = int(timediff.total_seconds())

        return duration >= self.update_delay

    def list_needs_regeneration(self, regenerate_list: bool) -> None:
        """
        Set whether the list needs an update.

            Parameters:
                regenerate_list (bool): True if the list needs to be regenerated
        """
        self.regenerate_list = regenerate_list

    def is_idle(self) -> bool:
        """
        Check whether the UI is considered idle;
        The UI is idle if nothing has updated last_action within
        the last idle_timeout seconds.

            Returns:
                (bool): True if idle, False if not idle
        """
        return (datetime.now(UTC) - self.last_action).seconds > self.idle_timeout

    def force_idle(self) -> None:
        """
        Set last_action far enough back so that the system is considered idle;
        this should be done when doing a force reload.
        """
        self.last_action = datetime.now(UTC) - timedelta(seconds=self.idle_timeout)

    def is_list_regenerated(self) -> bool:
        """
        Has the list been regenerated?

            Returns:
                (bool): True if the list has been regenerated, False if not
        """
        return not self.regenerate_list

    def select(self, selection: dict | None) -> None:
        """
        Select the current object.

            Parameters:
                selection (Type): A reference to the selected object
        """
        self.selected = selection

    def select_if_y(self, y: int, selection: dict) -> None:
        """
        Select the current object if y matches the current position.

            Parameters:
                y (int): The index to check against
                selection (Type): A reference to the object to (conditionally) select
        """
        if self.yoffset + self.curypos == y:
            self.select(selection)

    def refresh_selected(self) -> None:
        """
        Refresh the object selection if the list has been updated.
        """
        if not self.sorted_list or self.yoffset + self.curypos >= self.listlen:
            self.selected = None
        else:
            self.selected = self.sorted_list[self.yoffset + self.curypos]

    def is_selected(self, selected: dict | None) -> bool:
        """
        Check whether the referenced object is selected.

            Parameters:
                selected (Type): A reference to an object
            Returns:
                (bool): True if the object is selected, False if not
        """
        if selected is None:
            return False

        return self.selected == selected

    def get_selected(self) -> dict | None:
        """
        Return a reference to the selected object.

            Returns:
                (dict): A reference to the selected object, or None if no object is selected
        """
        return self.selected

    # Default behaviour:
    # timestamps enabled, no automatic updates, default sortcolumn = "status"
    def init_window(self, **kwargs: Any) -> None:
        """
        Initialise the main curses-window.

            Parameters:
                TODO
        """
        self.field_dict = deep_get(kwargs, DictPath("field_dict"), {})
        self.searchkey = ""
        self.sortcolumn = deep_get(kwargs, DictPath("sortcolumn"), "status")
        self.sortorder_reverse = deep_get(kwargs, DictPath("sortorder_reverse"), False)
        self.reversible = deep_get(kwargs, DictPath("reversible"), True)
        self.sortable = deep_get(kwargs, DictPath("sortable"), True)
        self.sortkey1, self.sortkey2 = self.get_sortkeys()
        update_delay: int = deep_get(kwargs, DictPath("update_delay"), -1)
        self.set_update_delay(update_delay)
        self.view = deep_get(kwargs, DictPath("view"))

        self.windowheader = deep_get(kwargs, DictPath("windowheader"), "")
        self.headerpad = None
        self.listpad = None
        self.infopad = None
        self.tspad = None
        self.logpad = None
        self.helptext = deep_get(kwargs, DictPath("helptext"))

        self.activatedfun = deep_get(kwargs, DictPath("activatedfun"))
        self.on_activation = deep_get(kwargs, DictPath("on_activation"), {})
        self.extraref = deep_get(kwargs, DictPath("extraref"))
        self.data = deep_get(kwargs, DictPath("data"))

        self.resize_window()

    def reinit_window(self, field_dict: dict, sortcolumn: str) -> None:
        """
        Reinitialise the main window.

            Parameters:
                field_dict (dict): The dict of field data
                sortcolumn (str): The name of the column to use when sorting the list
        """
        self.field_dict = field_dict
        self.searchkey = ""
        self.sortcolumn = sortcolumn
        self.sortkey1, self.sortkey2 = self.get_sortkeys()
        self.resize_window()

    # pylint: disable-next=too-many-branches
    def update_window(self, update: str = "true") -> None:
        """
        Update the main window.

            Parameters:
                update (str): Update the timestamp? (true, pending, false)
        """
        hline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#hline"))

        maxyx = self.stdscr.getmaxyx()
        if self.maxy != (maxyx[0] - 1) or self.maxx != (maxyx[1] - 1):
            self.resize_window()
        self.stdscr.erase()
        self.stdscr.border()
        # If we do not have sideborders we need to clear the sideborders we just painted,
        # just in case the content of the logpad is not wide enough to cover it
        if not CursesConfiguration.borders:
            for y in range(self.logpadypos, self.maxy - 1):
                self.addthemearray(self.stdscr,
                                   [ThemeStr(" ", ThemeAttr("main", "default"))],
                                   y=y, x=0)
                self.addthemearray(self.stdscr,
                                   [ThemeStr(" ", ThemeAttr("main", "default"))],
                                   y=y, x=self.maxx)

        self.draw_winheader()
        self.update_timestamp(update=update)

        if self.headerpad:
            self.headerpad.erase()
            # Whether to have one or two hlines depends on if we
            # overlap with the upper border or not
            if self.headerpadypos > 1:
                window_tee_hline(self.stdscr, self.headerpadypos - 1, 0, self.maxx)
            window_tee_hline(self.stdscr, self.headerpadypos + 1, 0, self.maxx)
            if not CursesConfiguration.borders:
                if self.headerpadypos > 1:
                    self.addthemearray(self.stdscr,
                                       [ThemeStr(hline, ThemeAttr("main", "default"))],
                                       y=self.headerpadypos - 1, x=0)
                    self.addthemearray(self.stdscr,
                                       [ThemeStr(hline, ThemeAttr("main", "default"))],
                                       y=self.headerpadypos - 1, x=self.maxx)
                self.addthemearray(self.stdscr,
                                   [ThemeStr(hline, ThemeAttr("main", "default"))],
                                   y=self.headerpadypos + 1, x=0)
                self.addthemearray(self.stdscr,
                                   [ThemeStr(hline, ThemeAttr("main", "default"))],
                                   y=self.headerpadypos + 1, x=self.maxx)
        elif self.listpad and not CursesConfiguration.borders:
            self.addthemearray(self.stdscr,
                               [ThemeStr(" ", ThemeAttr("main", "default"))],
                               y=self.listpadypos - 1, x=0)
            self.addthemearray(self.stdscr,
                               [ThemeStr(" ", ThemeAttr("main", "default"))],
                               y=self.listpadypos - 1, x=self.maxx)

        if self.logpad:
            if self.logpadypos > 2:
                window_tee_hline(self.stdscr, self.logpadypos - 1, 0, self.maxx)
            if CursesConfiguration.borders:
                window_tee_hline(self.stdscr, self.maxy - 2, 0, self.maxx)
                if self.tspad and self.tspadxpos != self.logpadxpos and self.loglen:
                    window_tee_vline(self.stdscr, self.logpadxpos - 1,
                                     self.logpadypos - 1, self.maxy - 2)
            else:
                # If the window lacks sideborders we want lines
                self.addthemearray(self.stdscr,
                                   [ThemeStr(hline, ThemeAttr("main", "default"))],
                                   y=self.logpadypos - 1, x=0)
                self.addthemearray(self.stdscr,
                                   [ThemeStr(hline, ThemeAttr("main", "default"))],
                                   y=self.logpadypos - 1, x=self.maxx)

        self.reset_update_delay()

    # pylint: disable-next=unused-argument
    def update_timestamp(self, ypos: int = 0, xpos: int = -1, update: str = "true") -> None:
        """
        Update the timestamp in the menu bar.

            Parameters:
                ypos (int): The y-position of the timestamp
                xpos (int): The x-position of the timestamp
                update (str): Update the timestamp? (true, pending, false)
        """
        if xpos == -1:
            xpos = self.maxx
        if update == "true" or self.last_timestamp_update is None:
            # Here we need to be sure to convert to local timezone,
            # since we're outputting this to the UI.
            self.last_timestamp_update = f"{datetime.now(UTC).astimezone():%Y-%m-%d %H:%M:%S}"
        urcorner = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#urcorner"))

        timestamparray: list[ThemeRef | ThemeStr] = []

        if self.helpstring:
            timestamparray += [
                ThemeStr(self.helpstring, ThemeAttr("main", "statusbar")),
                ThemeRef("separators", "statusbar"),
            ]
        if update == "pending":
            timestamparray += [
                ThemeRef("separators", "statusbar_pending"),
            ]
        timestamparray += [
            ThemeStr(self.last_timestamp_update, ThemeAttr("main", "last_update")),
        ]

        if CursesConfiguration.borders:
            timestamparray += [
                ThemeStr(urcorner, ThemeAttr("main", "default")),
            ]

        xpos -= themearray_len(timestamparray) - 1
        self.addthemearray(self.top_statusbar, timestamparray, y=0, x=xpos)

    def draw_winheader(self) -> None:
        """
        Draw the main window header.
        """
        if self.windowheader != "":
            ulcorner = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#ulcorner"))

            winheaderarray: list[ThemeRef | ThemeStr] = []

            if CursesConfiguration.borders:
                winheaderarray += [
                    ThemeStr(ulcorner, ThemeAttr("main", "default")),
                ]

            winheaderarray += [
                ThemeRef("separators", "mainheader_prefix"),
                ThemeStr(f"{self.windowheader}", ThemeAttr("main", "header")),
                ThemeRef("separators", "mainheader_suffix"),
            ]
            self.addthemearray(self.top_statusbar, winheaderarray, y=0, x=0)

    def refresh_window(self) -> None:
        """
        Refresh the main window.
        """
        if CursesConfiguration.borders:
            bl = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#llcorner"))
            br = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#lrcorner"))
            self.addthemearray(self.stdscr,
                               [ThemeStr(bl, ThemeAttr("main", "default"))],
                               y=self.maxy - 2, x=0)
            self.addthemearray(self.stdscr,
                               [ThemeStr(br, ThemeAttr("main", "default"))],
                               y=self.maxy - 2, x=self.maxx)

        # The extra status can change,
        # so we need to update the windowheader (which should not change)
        self.draw_winheader()

        mousestatus = "On" if get_mousemask() == -1 else "Off"
        mousearray: list[ThemeRef | ThemeStr] = [
            ThemeStr("Mouse: ", ThemeAttr("statusbar", "infoheader")),
            ThemeStr(f"{mousestatus}", ThemeAttr("statusbar", "highlight"))
        ]
        xpos = self.maxx - themearray_len(mousearray) + 1
        if self.bottom_statusbar is not None:
            self.addthemearray(self.bottom_statusbar, mousearray, y=0, x=xpos)
        ycurpos = self.curypos + self.yoffset
        maxypos = self.maxcurypos + self.maxyoffset
        if ycurpos >= 0 and maxypos >= 0:
            curposarray: list[ThemeRef | ThemeStr] = [
                ThemeStr("Line: ", ThemeAttr("statusbar", "infoheader")),
                ThemeStr(f"{ycurpos + 1}".rjust(len(str(maxypos + 1))),
                         ThemeAttr("statusbar", "highlight")),
                ThemeRef("separators", "statusbar_fraction"),
                ThemeStr(f"{maxypos + 1}", ThemeAttr("statusbar", "highlight"))
            ]
            xpos = self.maxx - themearray_len(curposarray) + 1
            if self.bottom_statusbar is not None:
                self.addthemearray(self.bottom_statusbar, curposarray, y=1, x=xpos)
        self.stdscr.noutrefresh()

    def resize_window(self) -> None:
        """
        Resize the main window; this should be called whenever a resize event is detected.
        """
        self.stdscr.erase()
        maxyx = self.stdscr.getmaxyx()
        self.miny = 0
        self.maxy = maxyx[0] - 1
        self.maxx = maxyx[1] - 1
        self.mincurypos = self.miny
        # screen position
        self.curypos = self.mincurypos
        # offset relative pad
        self.yoffset = 0
        self.selected_uid = None
        self.maxyoffset = 0
        self.xoffset = 0
        self.maxxoffset = 0

        self.resize_statusbars()
        self.resize_listpad(width=self.linelen)
        self.update_window()
        self.force_refresh()
        self.reselect_uid()

    def refresh_all(self) -> None:
        """
        Refresh the main window and all pads.
        """
        self.stdscr.touchwin()
        self.stdscr.noutrefresh()
        if self.infopad:
            self.refresh_infopad()
        if self.listpad:
            self.refresh_listpad()
        if self.logpad:
            self.refresh_logpad()
        if self.top_statusbar or self.bottom_statusbar:
            self.refresh_statusbars()
        self.refresh = True

    # For generic information
    # Pass -1 as width to the infopadminwidth
    def init_infopad(self, height: int, width: int, ypos: int, xpos: int, **kwargs: Any) -> None:
        """
        Initialise the infopad.

            Parameters:
                height (int): The height of the infopad
                width (int): The width of the infopad
                ypos (int): The y-position of the infopad
                xpos (int): The x-position of the infopad
                **kwargs (dict[str, Any]): Keyword arguments
                    labels (dict[str, Any]): A dict with labels
                    annotations (dict[str, Any]): A dict with annotations
        """
        self.infopadminwidth = self.maxx + 1
        self.infopadypos = ypos
        self.infopadxpos = xpos
        self.infopadheight = height
        self.infopadwidth = max(width, self.infopadminwidth)
        self.infopad = curses.newpad(max(self.infopadheight, self.maxy), self.infopadwidth)
        self.labels = get_labels(deep_get(kwargs, DictPath("labels"), {}))
        self.annotations = get_labels(deep_get(kwargs, DictPath("annotations"), {}))

    def resize_infopad(self, height: int, width: int) -> None:
        """
        Resize the infopad.

            Parameters:
                height (int): The height of the infopad (-1: keep current height)
                width (int): The width of the infopad (-1: keep current width)
        """
        if self.infopad is None:
            return
        self.infopadminwidth = self.maxx - self.infopadxpos
        if height != -1:
            self.infopadheight = height
        self.infopad.erase()
        if width != -1:
            self.infopadwidth = max(width, self.infopadminwidth)
        self.infopad.resize(max(self.infopadheight, self.maxy), self.infopadwidth)

    def refresh_infopad(self) -> None:
        """
        Refresh the infopad.
        """
        if self.infopad:
            height = self.infopadheight
            if CursesConfiguration.borders:
                if self.logpad is None and self.listpad is None:
                    height = self.maxy - 3
                try:
                    self.infopad.noutrefresh(0, 0, self.infopadypos,
                                             self.infopadxpos, height, self.maxx - 1)
                except curses.error:
                    pass
            else:
                if self.logpad is None and self.listpad is None:
                    height = self.maxy - 2
                try:
                    self.infopad.noutrefresh(0, 0, self.infopadypos, self.infopadxpos - 1,
                                             height, self.maxx)
                except curses.error:
                    pass

            # If there's no logpad and no listpad, then the infopad is responsible for scrollbars
            if self.listpad is None and self.logpad is None and CursesConfiguration.borders:
                self.upperarrow, self.lowerarrow, self.vdragger = \
                    scrollbar_vertical(self.stdscr, self.maxx, self.infopadypos,
                                       self.maxy - 3, self.infopadheight, self.yoffset,
                                       ThemeAttr("main", "boxdrawing"))
                self.leftarrow, self.rightarrow, self.hdragger = \
                    scrollbar_horizontal(self.stdscr, self.maxy - 2, self.infopadxpos,
                                         self.maxx - 1, self.infopadwidth - 1, self.xoffset,
                                         ThemeAttr("main", "boxdrawing"))

    def init_listpad(self, width: int, ypos: int, xpos: int, **kwargs: Any) -> None:
        """
        Initialise optionally scrollable lists of information listpad.

            Parameters:
                width (int): The width of the listpad, or -1 to use listpadminwidth
                ypos (int): The y-position of the listpad
                xpos (int): The x-position of the listpad
                **kwargs (dict[str, Any]): Keyword arguments
                    header (bool): True to generate a headerpad,
                                   False to not generate a headerpad
        """
        self.listpadminwidth = self.maxx
        header: bool = deep_get(kwargs, DictPath("header"), True)

        if header:
            self.headerpadypos = ypos
            self.headerpadxpos = xpos
            self.headerpadheight = 1
            self.headerpadwidth = self.listpadminwidth
            self.listpadypos = ypos + 2
            self.headerpad = curses.newpad(self.headerpadheight, self.headerpadwidth)
        else:
            self.listpadypos = ypos
        self.listpadxpos = xpos
        self.listpadheight = self.maxy - 2 - self.listpadypos
        self.listpadwidth = max(width, self.listpadminwidth)
        self.listpad = curses.newpad(self.listpadheight, self.listpadwidth)
        self.curypos = 0
        self.yoffset = 0
        self.select(None)

    def resize_listpad(self, width: int) -> None:
        """
        Resize the listpad.

            Parameters:
                width (int): The width of the listpad (-1 to keep the current width)
        """
        if self.listpad is None:
            return
        self.listpadheight = self.maxy - 2 - self.listpadypos
        self.listpadminwidth = self.maxx
        self.listpad.erase()
        if width != -1:
            self.listpadwidth = max(width + 1, self.listpadminwidth)
        else:
            width = self.listpadwidth

        if CursesConfiguration.borders:
            self.maxcurypos = min(self.listpadheight - 1, self.listlen - 1)
        else:
            self.maxcurypos = min(self.listpadheight, self.listlen - 1)
        self.maxyoffset = self.listlen - (self.maxcurypos - self.mincurypos) - 1
        self.headerpadwidth = self.listpadwidth
        self.maxxoffset = max(0, self.listpadwidth - self.listpadminwidth)

        if self.headerpad and self.headerpadheight > 0:
            self.headerpad.resize(self.headerpadheight, self.headerpadwidth)
        if self.listpadheight > 0:
            self.listpad.resize(max(self.listpadheight, self.maxy), self.listpadwidth)
        self.curypos = min(self.curypos, self.maxcurypos)
        self.yoffset = min(self.yoffset, self.maxyoffset)
        self.reselect_uid()

    def refresh_listpad(self) -> None:
        """
        Refresh the listpad.
        """
        xpos = self.listpadxpos
        maxx = self.maxx - 1
        if not CursesConfiguration.borders:
            xpos -= 1
            maxx = self.maxx
        if self.headerpad:
            try:
                self.headerpad.noutrefresh(0, self.xoffset, self.headerpadypos,
                                           xpos, self.headerpadypos, maxx)
            except curses.error:
                pass
        if self.listpad:
            if CursesConfiguration.borders:
                try:
                    self.listpad.noutrefresh(0, self.xoffset, self.listpadypos,
                                             xpos, self.maxy - 3, maxx)
                except curses.error:
                    pass
                self.upperarrow, self.lowerarrow, self.vdragger = \
                    scrollbar_vertical(self.stdscr, x=maxx + 1, miny=self.listpadypos,
                                       maxy=self.maxy - 3, height=self.listlen,
                                       yoffset=self.yoffset,
                                       clear_color=ThemeAttr("main", "boxdrawing"))
                self.leftarrow, self.rightarrow, self.hdragger = \
                    scrollbar_horizontal(self.stdscr, y=self.maxy - 2, minx=self.listpadxpos,
                                         maxx=maxx, width=self.listpadwidth - 1,
                                         xoffset=self.xoffset,
                                         clear_color=ThemeAttr("main", "boxdrawing"))
            else:
                try:
                    self.listpad.noutrefresh(0, self.xoffset, self.listpadypos,
                                             xpos, self.maxy - 2, maxx)
                except curses.error:
                    pass

    def recalculate_logpad_xpos(self, tspadxpos: int = -1,
                                timestamps: bool | None = None) -> None:
        """
        Recalculate the x-position of the logpad. This is necessary when toggling timestamps.

            Parameters:
                tspadxpos (int): The x-position of the timestamp pad
                timestamps (bool): Are the timestamps enabled?
        """
        if tspadxpos == -1 and self.tspadxpos is None:
            raise ProgrammingError("logpad is not initialised and no tspad xpos provided")

        if timestamps is None:
            timestamps = self.tspadxpos != self.logpadxpos

        self.tspadxpos = tspadxpos

        if not timestamps:
            self.tspadwidth = 0
            self.logpadxpos = self.tspadxpos
        else:
            self.tspadwidth = len("YYYY-MM-DD HH:MM:SS")
            # self.tspadwidth = len("YYYY-MM-DD")
            self.logpadxpos = self.tspadxpos + self.tspadwidth + 1

    # For (optionally) scrollable log of information with optional timestamps
    # The log widget behaves a bit differently than the list widget;
    # to avoid a lot of wasted memory when most log messages are short and there's one
    # string that can go for miles (if you know what I mean), we keep the pad
    # the same height as the visible area, and only update the content of the pad
    # as the yoffset changes.  The pad is still variable width though.
    #
    # Pass -1 as width to use logpadminwidth
    def init_logpad(self, width: int, ypos: int, xpos: int, **kwargs: Any) -> None:
        """
        Initialise the logpad.

            Parameters:
                width (int): The width of the logpad
                ypos (int): The y-position of the logpad
                xpos (int): The x-position of the logpad
                **kwargs (dict[str, Any]): Keyword arguments
                    timestamp (bool): True to generate a timestamp pad,
                                      False not to generate a timestamp pad
        """
        timestamps: bool = deep_get(kwargs, DictPath("timestamps"), True)

        self.match_index = None
        self.search_matches = set()

        self.logpadheight = self.maxy - ypos - 2
        self.recalculate_logpad_xpos(tspadxpos=xpos, timestamps=timestamps)
        if timestamps:
            self.tspadypos = ypos
            self.tspadheight = self.logpadheight
            self.tspad = curses.newpad(self.tspadheight + 1, self.tspadwidth)
        else:
            self.tspad = None
        self.logpadypos = ypos
        self.logpadminwidth = self.maxx - self.logpadxpos
        if width == -1:
            self.logpadwidth = self.logpadminwidth
        else:
            self.logpadwidth = max(width, self.logpadminwidth)
        self.logpad = curses.newpad(self.logpadheight + 1, self.logpadwidth)
        self.loglen = 0

    def resize_logpad(self, height: int, width: int) -> None:
        """
        Resize the logpad.

            Parameters:
                height (int): The height of the logpad (-1: keep current height)
                width (int): The width of the logpad (-1: keep current width)
        """
        self.recalculate_logpad_xpos(tspadxpos=self.tspadxpos)
        if height != -1:
            if CursesConfiguration.borders:
                self.tspadheight = height
                self.logpadheight = height
            else:
                self.tspadheight = height + 1
                self.logpadheight = height + 1
        if width != -1:
            self.logpadminwidth = self.maxx - self.logpadxpos
            self.logpadwidth = max(width, self.logpadminwidth) + 1

        if self.logpadheight > 0:
            if self.tspad and self.tspadxpos != self.logpadxpos:
                self.tspad.resize(self.tspadheight + 1, self.tspadwidth + 1)
            if self.logpad:
                self.logpad.resize(self.logpadheight + 1, self.logpadwidth + 1)
        self.maxyoffset = max(0, self.loglen - self.logpadheight)
        self.maxxoffset = max(0, self.logpadwidth - self.logpadminwidth - 1)
        self.yoffset = min(self.yoffset, self.maxyoffset)

    def refresh_logpad(self) -> None:
        """
        Refresh the logpad.
        """
        if self.logpad is None:
            return

        self.yoffset = min(self.yoffset, self.maxyoffset)
        self.xoffset = min(self.xoffset, self.maxxoffset)

        tspadxpos = self.tspadxpos
        logpadxpos = self.logpadxpos
        if not CursesConfiguration.borders:
            tspadxpos -= 1
            logpadxpos -= 1
        if self.tspad and self.tspadxpos != self.logpadxpos:
            hline = deep_get(ThemeStrConfiguration.theme, DictPath("boxdrawing#hline"))
            if CursesConfiguration.borders:
                for i in range(self.tspadwidth):
                    self.addthemearray(self.stdscr,
                                       [ThemeStr(hline, ThemeAttr("main", "default"))],
                                       y=self.maxy - 2, x=1 + i)
                try:
                    self.tspad.noutrefresh(0, 0, self.tspadypos, tspadxpos,
                                           self.maxy - 3, self.tspadwidth)
                except curses.error:
                    pass
            else:
                try:
                    self.tspad.noutrefresh(0, 0, self.tspadypos, tspadxpos,
                                           self.maxy - 2, self.tspadwidth - 1)
                except curses.error:
                    pass
        if CursesConfiguration.borders:
            try:
                self.logpad.noutrefresh(0, self.xoffset, self.logpadypos, logpadxpos,
                                        self.maxy - 3, self.maxx - 1)
            except curses.error:
                pass
            self.upperarrow, self.lowerarrow, self.vdragger = \
                scrollbar_vertical(self.stdscr, self.maxx, self.logpadypos, self.maxy - 3,
                                   self.loglen, self.yoffset, ThemeAttr("main", "boxdrawing"))
            self.leftarrow, self.rightarrow, self.hdragger = \
                scrollbar_horizontal(self.stdscr, self.maxy - 2, logpadxpos, self.maxx - 1,
                                     self.logpadwidth, self.xoffset,
                                     ThemeAttr("main", "boxdrawing"))
        else:
            try:
                self.logpad.noutrefresh(0, self.xoffset, self.logpadypos, logpadxpos,
                                        self.maxy - 2, self.maxx)
            except curses.error:
                pass

    def toggle_timestamps(self, timestamps: bool | None = None) -> None:
        """
        Toggle timestamps on/off.

            Parameters:
                timestamps (bool): True to enable timestamps,
                                   False to disable timestamps,
                                   None to toggle the timestamps
        """
        if timestamps is None:
            timestamps = self.tspadxpos == self.logpadxpos

        self.recalculate_logpad_xpos(tspadxpos=self.tspadxpos, timestamps=timestamps)

    def toggle_borders(self, **kwargs: Any) -> None:
        """
        Toggle screen border on/off.

            Parameters:
                **kwargs (dict[str, Any]): Keyword arguments
                    borders (bool): True to enable borders,
                                    False to disable borders;
                                    None to toggle borders
        """
        borders: bool | None = deep_get(kwargs, DictPath("borders"))

        if borders is None:
            CursesConfiguration.borders = not CursesConfiguration.borders
        else:
            CursesConfiguration.borders = borders

        self.recalculate_logpad_xpos(tspadxpos=self.tspadxpos)
        self.resize_listpad(-1)

    def init_statusbars(self) -> None:
        """
        Initialise the statusbars.
        """
        self.resize_statusbars()

    def refresh_statusbars(self) -> None:
        """
        Refresh the statusbars.
        """
        if self.top_statusbar is not None:
            window_tee_hline(self.top_statusbar, self.top_statusbarypos, 0, self.maxx, tee=False)
            self.update_timestamp(update="false")
            self.draw_winheader()
            try:
                self.top_statusbar.noutrefresh(0, 0,
                                               self.top_statusbarypos, 0,
                                               self.maxy, self.maxx)
            except curses.error:
                pass

        if self.bottom_statusbar is not None:
            col, __discard = themeattr_to_curses(ThemeAttr("statusbar", "default"))
            self.bottom_statusbar.bkgd(" ", col)
            try:
                self.bottom_statusbar.noutrefresh(0, 0,
                                                  self.bottom_statusbarypos, 0,
                                                  self.maxy, self.maxx)
            except curses.error:
                pass

    def resize_statusbars(self) -> None:
        """
        Trigger the statusbar to be resized.
        """
        self.top_statusbarypos = 0
        self.bottom_statusbarypos = self.maxy - 1

        if self.top_statusbar is not None:
            self.top_statusbar.erase()
            self.top_statusbar.resize(1, self.maxx + 1)
        else:
            self.top_statusbar = curses.newpad(1, self.maxx + 1)

        if self.bottom_statusbar is not None:
            self.bottom_statusbar.erase()
            self.bottom_statusbar.resize(2, self.maxx + 1)
        else:
            self.bottom_statusbar = curses.newpad(2, self.maxx + 1)

    # pylint: disable-next=too-many-locals,too-many-branches
    def populate_custom_statusmsgs(self, status_fields: list[dict],
                                   src_vars: dict[str, Any], src_obj: dict[str, Any]) -> None:
        """
        Populate the status array.

            Parameters:
                status_fields ([dict]): The status fields to add to the status array
                src_vars (dict): The data from view variables
                src_obj (dict): The data from the object being processed
        """
        statusarray1: list[ThemeRef | ThemeStr] = []
        statusarray2: list[ThemeRef | ThemeStr] = []

        # If we don't have a statusbar configured we we be able to add anything to it.
        if self.bottom_statusbar is None:
            return

        # The data in some fields might become shorter, so we need to trigger an erase.
        self.bottom_statusbar.erase()

        for status_data in status_fields:
            key = deep_get(status_data, DictPath("key"), "<unset>")
            source = deep_get(status_data, DictPath("source"), "var")
            obj = src_vars
            value_path = deep_get(status_data, DictPath("path"))
            default_status = deep_get(status_data, DictPath("default"))
            transform = deep_get(status_data, DictPath("transform"), {})
            row = deep_get(status_data, DictPath("row"), 2)

            if source == "config":
                obj = cmtlib.cmtconfig
            elif source == "var":
                obj = src_vars
            elif source == "obj":
                obj = src_obj
            elif source == "constant":
                # This will just be ignored, so the default source is just fine.
                pass

            value = deep_get(obj, value_path, default_status)

            if transform and deep_get(transform, DictPath("rule")) == "map":
                tmp_value = deep_get(transform, DictPath(f"map#{value}"))
                if "value" in tmp_value:
                    value = tmp_value["value"]
                if "lookup" in tmp_value:
                    source = deep_get(tmp_value, DictPath("lookup#source"), "var")
                    path = deep_get(tmp_value, DictPath("lookup#path"))
                    if source == "config":
                        obj = cmtlib.cmtconfig
                    elif source == "var":
                        obj = src_vars
                    elif source == "obj":
                        obj = src_obj
                    value = deep_get(obj, DictPath(path), value)

            value = str(value)

            if row == 1:
                if statusarray1:
                    statusarray1 += [ThemeRef("separators", "statusbar")]
                statusarray1 += [
                    ThemeStr(key, ThemeAttr("statusbar", "infoheader")),
                ]
                if source != "constant":
                    statusarray1 += [
                        ThemeStr(value, ThemeAttr("statusbar", "highlight")),
                    ]
            else:
                if statusarray2:
                    statusarray2 += [ThemeRef("separators", "statusbar")]
                statusarray2 += [
                    ThemeStr(key, ThemeAttr("statusbar", "infoheader")),
                ]
                if source != "constant":
                    statusarray2 += [
                        ThemeStr(value, ThemeAttr("statusbar", "highlight")),
                    ]

        addthemearray(self.bottom_statusbar, statusarray1, y=0, x=0)
        addthemearray(self.bottom_statusbar, statusarray2, y=1, x=0)

    # pylint: disable-next=too-many-locals
    def addthemearray(self, win: curses.window | None,
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
                (int, int): The new (y, x) coordinates
        """
        y: int = deep_get(kwargs, DictPath("y"), -1)
        x: int = deep_get(kwargs, DictPath("x"), -1)
        deleted: bool = deep_get(kwargs, DictPath("deleted"), False)

        if win is None:
            return y, x

        for item in themearray_flatten(array):
            if deleted:
                item.set_themeattr(ThemeAttr("types", "deleted"))
            string, attr = themestring_to_cursestuple(item)
            # If there still are remaining <NUL> occurences, replace them
            string = string.replace("\x00", "<NUL>")

            maxy, maxx = win.getmaxyx()
            cury, curx = win.getyx()

            newmaxy = max(y, maxy)
            newmaxx = max(maxx, len(string) + curx + 1)

            if win != self.stdscr:
                win.resize(newmaxy, newmaxx)
            elif win == self.stdscr and (maxy, maxx) != (newmaxy, newmaxx):
                # If the string to print is *exactly* maxx == len(string) + curx,
                # then we check if we can print the last character using addch(),
                # otherwise we give up.
                if (maxy, maxx) == (newmaxy, len(string) + curx):
                    try:
                        win.addch(y, maxx - 1, string[-1:], attr)
                        win.addstr(string[0:-1], attr)
                    except curses.error:
                        cury, curx = win.getyx()
                        return cury, curx
                else:
                    # If the message would resize the window,
                    # just pretend success instead of raising an exception
                    cury, curx = win.getyx()
                    return cury, curx

            try:
                win.addstr(y, x, string, attr)
            except curses.error:
                pass
            y, x = win.getyx()
        return y, x

    def move_xoffset_abs(self, position: int) -> None:
        """
        Move the x-offset to an absolute position.

            Parameters:
                position (int): The new x-position (-1: the last possible x-offset)
        """
        if CursesConfiguration.borders:
            sideadjust = 0
        else:
            sideadjust = 2
        if position == -1:
            self.xoffset = self.maxxoffset - sideadjust
        elif position == 0:
            self.xoffset = 0
        else:
            self.xoffset = max(0, position)
            self.xoffset = min(self.xoffset, self.maxxoffset - sideadjust)
        self.refresh = True

    def move_yoffset_abs(self, position: int) -> None:
        """
        Move the y-offset to an absolute position.

            Parameters:
                position (int): The new y-position (-1: the last possible y-offset)
        """
        if position == -1:
            self.yoffset = self.maxyoffset
        elif position == 0:
            self.yoffset = 0
        else:
            self.yoffset = max(0, position)
            self.yoffset = min(self.yoffset, self.maxyoffset)
        self.refresh = True
        self.reselect_uid()

    def move_xoffset_rel(self, movement: int) -> None:
        """
        Move the x-offset relative to the current position.

            Parameters:
                movement (int): The number lines to move the offset left/right.
        """
        if CursesConfiguration.borders:
            sideadjust = 0
        else:
            sideadjust = 2
        self.xoffset = max(0, self.xoffset + movement)
        self.xoffset = min(self.xoffset, self.maxxoffset - sideadjust)
        self.refresh = True

    def move_yoffset_rel(self, movement: int) -> None:
        """
        Move the y-offset relative to the current position.

            Parameters:
                movement (int): The number lines to move the offset up/down.
        """
        self.yoffset = max(0, self.yoffset + movement)
        self.yoffset = min(self.maxyoffset, self.yoffset)
        self.refresh = True
        self.reselect_uid()

    def move_cur_abs(self, position: int) -> None:
        """
        Move the cursor y-position to an absolute position.
        Note: Only 0 (first line) and -1 (last line) are supported.

            Parameters:
                position (int): The new y-position
        """
        if position == -1:
            self.curypos = self.maxcurypos
            self.yoffset = self.maxyoffset
        elif position == 0:
            self.curypos = self.mincurypos
            self.yoffset = 0
        else:
            raise ProgrammingError("FIXME")
        self.list_needs_regeneration(True)
        self.reselect_uid()

    def move_cur_with_offset(self, movement: int) -> None:
        """
        Move the cursor y-position relative to the current position.

            Parameters:
                movement (int): The number lines to the cursor move up/down.
        """
        if self.curypos == -1 or self.yoffset == -1:
            self.curypos = 0
            self.yoffset = 0
        newcurypos = self.curypos + movement
        newyoffset = self.yoffset

        # If we are being asked to move forward but we are already
        # at the end of the list, it is prudent not to move,
        # even if the caller so requests.
        # It is just good manners, really.
        if self.yoffset + newcurypos > self.listlen:
            newcurypos = min(newcurypos, self.maxcurypos)
            newyoffset = self.maxyoffset
        elif newcurypos > self.maxcurypos:
            newyoffset = min(self.yoffset - (self.maxcurypos - newcurypos), self.maxyoffset)
            newcurypos = self.maxcurypos
        elif newcurypos < self.mincurypos:
            newyoffset = max(self.yoffset + (newcurypos - self.mincurypos), 0)
            newcurypos = self.mincurypos

        if self.curypos != newcurypos or self.yoffset != newyoffset:
            self.curypos = newcurypos
            self.yoffset = newyoffset
            self.list_needs_regeneration(True)
        self.reselect_uid()

    def find_all_matches_by_searchkey(self,
                                      messages: list[list[ThemeRef | ThemeStr] | str],
                                      searchkey: str) -> None:
        """
        Given a search key, find all lines that matches that search key,
        and update the search_matches list with their indices.

            Parameters:
                messages ([[ThemeRef | ThemeStr] | str]): The messages to search through
                searchkey (str): The search key
        """
        self.match_index = None
        self.search_matches.clear()

        if not searchkey or not messages:
            return

        for y, msg in enumerate(messages):
            # The messages can either be raw strings,
            # or themearrays, so we need to flatten them first
            if isinstance(msg, str):
                message = msg
            else:
                message = themearray_to_string(msg)
            # Case-insensitive search
            if searchkey.lower() in message.lower():
                self.search_matches.add(y)

    def find_next_match(self) -> None:
        """
        Find the next matching entry in the log and move the y-offset to that entry
        (or to the max y-offset, if the match is at the bottom of the log).
        """
        start = self.match_index
        if start is None:
            start = self.yoffset
        for y in range(start, self.loglen):
            if y in self.search_matches and self.match_index != y:
                self.match_index = y
                self.yoffset = min(y, self.maxyoffset)
                break
        self.reselect_uid()

    def find_prev_match(self) -> None:
        """
        Find the previous matching entry in the log and move the y-offset to that entry.
        """
        end = self.match_index
        if end is None:
            end = self.yoffset
        for y in reversed(range(end)):
            # We do not want to return the same match over and over...
            if y in self.search_matches and self.match_index != y:
                self.match_index = y
                self.yoffset = min(y, self.maxyoffset)
                break
        self.reselect_uid()

    def next_line_by_severity(self, severities: list[LogLevel], timestamps: list[datetime]) -> None:
        """
        Find the next line that has a severity < NOTICE,
        and move the the y-offset to that position.

            Parameters:
                severities ([LogLevel]): A list of the severities
        """
        newoffset = self.yoffset

        if severities is None or self.yoffset + 1 >= self.maxyoffset:
            return

        for y in range(self.yoffset + 1, self.maxyoffset):
            try:
                # If we don't have a timestamp this is a block, so we don't
                # care about its individual lines; instead we just skip past it.
                if severities[y] < LogLevel.NOTICE and timestamps[y] != none_timestamp():
                    newoffset = y
                    break
            except IndexError:
                # We've run out of timestamps; just jump to the next elevated line.
                newoffset = y
                break

        self.yoffset = min(newoffset, self.maxyoffset)
        self.refresh = True

    # Find the prev line that has severity > NOTICE
    def prev_line_by_severity(self, severities: list[LogLevel], timestamps: list[datetime]) -> None:
        """
        Find the previous line that has a severity < NOTICE,
        and move the the y-offset to that position.

            Parameters:
                severities ([LogLevel]): A list of the severities
        """
        if severities is None or self.yoffset - 1 <= 0:
            return

        for y in range(self.yoffset - 1, -1, -1):
            if severities[y] >= LogLevel.NOTICE:
                continue

            try:
                # If we don't have a timestamp this is a block, so we don't
                # care about its individual lines; instead we just skip past it.
                if timestamps[y] != none_timestamp():
                    self.yoffset = y
                    break
            except IndexError:
                # We've run out of timestamps; since we're going backwards this likely means
                # that we don't have any timestamps at all; since we had a match,
                # let's jump to this.
                self.yoffset = y
                break

        self.refresh = True

    def next_by_sortkey(self, info: list[dict]) -> None:
        """
        Jump to the next list entry by sortkey; this is used in listpads;
        this doesn't use a user-provided sortkey. Instead it uses a bit of magic:
        * For namespaces it jumps to the next namespace (since there typically several
          entries in each namespace).
        * For names it jumps to the next (represented) letter of the alphabet.
        * For status it jumps to the next status.
        * For node it jumps to the next node.
        * For other types it just jumps to the next entry.

            Parameters:
                info ([Info]): The list information
        """
        if not self.sortkey1:
            return

        pos = self.curypos + self.yoffset
        y = 0
        newpos = 0
        current = ""
        sortkey1, sortkey2 = self.get_sortkeys()
        sortkey = sortkey2 if sortkey1 == "status_group" else sortkey1

        try:
            for entry in natsorted(info, key=itemgetter(sortkey1, sortkey2),
                                   reverse=self.sortorder_reverse):
                entryval = deep_get(entry, DictPath(sortkey))

                # OK, from here we want to go to next entry
                if y == pos:
                    if sortkey == "age" or self.sortkey1 == "seen":
                        current = seconds_to_age(entryval)
                    else:
                        current = entryval
                elif y > pos:
                    if sortkey == "name":
                        if current[0] != entryval[0]:
                            newpos = y - pos
                            break
                    elif sortkey == "age" or self.sortkey1 == "seen":
                        if current != seconds_to_age(entryval):
                            newpos = y - pos
                            break
                    else:
                        if current != entryval:
                            newpos = y - pos
                            break
                y += 1
        except TypeError:
            return

        # If we do not match we will just end up with the old pos
        self.move_cur_with_offset(newpos)

    # pylint: disable-next=too-many-branches
    def prev_by_sortkey(self, info: list[dict]) -> None:
        """
        Jump to the previous list entry by sortkey; this is used in listpads;
        this doesn't use a user-provided sortkey. Instead it uses a bit of magic:
        * For namespaces it jumps to the previous namespace (since there typically several
          entries in each namespace).
        * For names it jumps to the previous (represented) letter of the alphabet.
        * For status it jumps to the previous status.
        * For node it jumps to the previous node.
        * For other types it just jumps to the previous entry.

            Parameters:
                info ([Info]): The list information
        """
        if self.sortkey1 is None:
            return

        pos = self.curypos + self.yoffset
        y = 0
        newpos = 0
        current = None
        sortkey1, sortkey2 = self.get_sortkeys()
        sortkey = sortkey2 if sortkey1 == "status_group" else sortkey1

        try:
            # Search backward within sort category
            # prev namespace when sorted by namespace
            # prev (existing) letter when sorted by name
            # prev status when sorted by status
            # prev node when sorted by node
            for entry in natsorted(info, key=itemgetter(sortkey1, sortkey2),
                                   reverse=self.sortorder_reverse):
                entryval = deep_get(entry, DictPath(sortkey))
                if current is None:
                    if sortkey == "age" or self.sortkey1 == "seen":
                        current = seconds_to_age(entryval)
                    else:
                        current = entryval

                if y == pos:
                    break

                if sortkey == "name" and current is not None and current:
                    if current[0] != entryval[0]:
                        current = entryval
                        newpos = y - pos
                elif sortkey == "age":
                    if current != seconds_to_age(deep_get(entry, DictPath(sortkey))):
                        current = seconds_to_age(entryval)
                        newpos = y - pos
                else:
                    if current != entryval:
                        current = entryval
                        newpos = y - pos
                y += 1
        except TypeError:
            return

        # If we do not match we will just end up with the old pos
        if not newpos:
            self.move_cur_abs(0)
        else:
            self.move_cur_with_offset(newpos)

    # pylint: disable-next=too-many-branches
    def find_next_by_sortkey(self, info: list[dict], searchkey: str) -> None:
        """
        Search a list using search key and jump to the next matching entry.

            Parameters:
                info ([Info]): The list information
                searchkey (str): The search key
        """
        pos = self.curypos + self.yoffset
        offset = 0

        # Search within sort category
        try:
            sorted_list = natsorted(info, key=itemgetter(self.sortkey1, self.sortkey2),
                                    reverse=self.sortorder_reverse)
        except TypeError:
            return

        negate_match: bool = False
        case_insensitive: bool = False

        # Since a regex cannot start with * or ? we use those to toggle behaviour
        if searchkey.startswith(("*?", "?*")):
            negate_match = True
            case_insensitive = True
            searchkey = searchkey[2:]
        elif searchkey.startswith("?"):
            negate_match = True
            searchkey = searchkey[1:]
        elif searchkey.startswith("*"):
            case_insensitive = True
            searchkey = searchkey[1:]

        try:
            if case_insensitive:
                searchkey_regex: re.Pattern[str] = re.compile(searchkey, re.IGNORECASE)
            else:
                searchkey_regex = re.compile(searchkey)
        except re.PatternError:
            return

        match = False
        for y in range(pos, len(sorted_list)):
            tmp2 = deep_get(sorted_list[y], DictPath(self.sortcolumn))
            if self.sortkey1 in ("age", "first_seen", "last_restart", "seen"):
                tmp2 = [seconds_to_age(tmp2)]
            else:
                if isinstance(tmp2, (list, tuple)):
                    if isinstance(tmp2[0], tuple):
                        tmp3: list = []
                        for t in tmp2:
                            tmp3 += map(str, t)
                        tmp2 = tmp3
                    else:
                        tmp2 = map(str, tmp2)
                else:
                    tmp2 = [str(tmp2)]
            for part in tmp2:
                if part and bool(searchkey_regex.search(part)) != negate_match \
                        and (offset := y - pos) > 0:
                    match = True
                    break
            if match:
                break

        # If we do not match we will just end up with the old pos
        self.move_cur_with_offset(offset)

    # pylint: disable-next=too-many-branches
    def find_prev_by_sortkey(self, info: list[dict], searchkey: str) -> None:
        """
        Search a list using search key and jump to the previous matching entry.

            Parameters:
                info ([Info]): The list information
                searchkey (str): The search key
        """
        pos = self.curypos + self.yoffset
        offset = 0

        # Search within sort category
        try:
            sorted_list = natsorted(info, key=itemgetter(self.sortkey1, self.sortkey2),
                                    reverse=self.sortorder_reverse)
        except TypeError:
            return

        negate_match: bool = False
        case_insensitive: bool = False

        # Since a regex cannot start with * or ? we use those to toggle behaviour
        if searchkey.startswith(("*?", "?*")):
            negate_match = True
            case_insensitive = True
            searchkey = searchkey[2:]
        elif searchkey.startswith("?"):
            negate_match = True
            searchkey = searchkey[1:]
        elif searchkey.startswith("*"):
            case_insensitive = True
            searchkey = searchkey[1:]

        try:
            if case_insensitive:
                searchkey_regex: re.Pattern[str] = re.compile(searchkey, re.IGNORECASE)
            else:
                searchkey_regex = re.compile(searchkey)
        except re.PatternError:
            return

        match = False
        for y in reversed(range(pos)):
            tmp2 = deep_get(sorted_list[y], DictPath(self.sortcolumn))
            if self.sortkey1 in ("age", "seen"):
                tmp2 = [seconds_to_age(tmp2)]
            else:
                if isinstance(tmp2, (list, tuple)):
                    tmp2 = map(str, tmp2)
                else:
                    tmp2 = [str(tmp2)]
            for part in tmp2:
                if part and bool(searchkey_regex.search(part)) != negate_match \
                        and (offset := y - pos) < 0:
                    match = True
                    break
            if match:
                break

        # If we do not match we will just end up with the old pos
        self.move_cur_with_offset(offset)

    def goto_first_match_by_name_namespace(self, name: str | None,
                                           namespace: str | None) -> dict | None:
        """
        This function is used to find the first match based on command line input
        The sort order used will still be the default, to ensure that the partial
        match ends up being the first.

            Parameters:
                name (str): The name to search for
                namespace (str): The namespace to search for
            Returns:
                (dict): The unique match, the first partial match
                        if no unique match is found, or None if no match is found
        """
        if not self.info or not name or "name" not in self.info[0]:
            return None

        # Search within sort category
        try:
            sorted_list = natsorted(self.info, key=itemgetter(self.sortkey1, self.sortkey2),
                                    reverse=self.sortorder_reverse)
        except TypeError:
            return None

        first_match = None
        unique_match = None
        match_count = 0

        for y, listitem in enumerate(sorted_list):
            if "namespace" in sorted_list[0] and namespace \
                    and deep_get(listitem, DictPath("namespace")) == namespace:
                continue

            if deep_get(listitem, DictPath("name")) == name:
                first_match = y
                match_count = 1
                break

            if deep_get(listitem, DictPath("name")).startswith(name):
                if not first_match:
                    first_match = y
                match_count += 1

        if first_match:
            self.move_cur_with_offset(first_match)
        if match_count == 1:
            unique_match = deep_get(sorted_list[self.curypos + self.yoffset], DictPath("ref"))

        return unique_match

    def next_sortcolumn(self) -> None:
        """
        Switch to the next sort column.
        """
        if self.sortcolumn == "":
            return

        match = 0
        for field in self.field_dict:
            if self.field_dict[field].get("skip", False):
                continue
            if match == 1:
                self.sortcolumn = field
                break
            if field == self.sortcolumn:
                match = 1

        self.sortkey1, self.sortkey2 = self.get_sortkeys()
        self.sort_triggered = True

    def prev_sortcolumn(self) -> None:
        """
        Switch to the previous sort column.
        """
        if self.sortcolumn == "":
            return

        match = 0
        for field in reversed(self.field_dict):
            if match == 1:
                self.sortcolumn = field
                break
            if field == self.sortcolumn:
                match = 1

        self.sortkey1, self.sortkey2 = self.get_sortkeys()
        self.sort_triggered = True

    def get_sortcolumn(self) -> str:
        """
        Return the current sort column.

            Returns:
                (str): The current sort column.
        """
        return self.sortcolumn

    def get_sortkeys(self) -> tuple[str, str]:
        """
        Return the sort key tuple.

            Returns:
                ((str, str)): The primary and secondary sort keys.
        """
        if not self.field_dict:
            # We do not really care about what the sortkeys are; we do not have a list to sort
            # but if we return valid strings we can at least pacify the type checker
            return "", ""

        field = self.field_dict.get(self.sortcolumn)

        if field is None:
            raise ValueError(f"Invalid sortcolumn: {self.sortcolumn} does not exist "
                             "in field_dict:\n"
                             f"    Valid fields are: {list(self.field_dict)}")

        sortkey1 = self.field_dict[self.sortcolumn]["sortkey1"]
        sortkey2 = self.field_dict[self.sortcolumn]["sortkey2"]
        return sortkey1, sortkey2

    # noqa: E501 pylint: disable-next=too-many-return-statements,too-many-locals,too-many-statements,too-many-branches
    def handle_mouse_events(self, win: curses.window,
                            sorted_list: list[dict], **kwargs: Any) -> Retval:
        """
        Handle mouse events.

            Parameters:
                win (curses.window): The curses window to operate on
                sorted_list ([Info]): The sorted list information
                **kwargs (dict[str, Any]): Keyword arguments
                    activatedfun (Callable): The function to call on activation
                    extraref (str): An alternate view reference: This should probably be redesigned
                    data (bool): FIXME
            Returns:
                (Retval): The return value
        """
        activatedfun: Callable | None = deep_get(kwargs, DictPath("activatedfun"))
        extraref: str | None = deep_get(kwargs, DictPath("extraref"))
        data: bool | None = deep_get(kwargs, DictPath("data"))
        selected: Any | None = False

        try:
            _eventid, x, y, _z, bstate = curses.getmouse()
        except curses.error:
            # Most likely mouse is not supported
            return Retval.NOMATCH

        if win == self.listpad:
            if self.listpad is None:
                return Retval.NOMATCH
            cypos = self.listpadypos
            cxpos = self.listpadxpos
            cheight = self.listpadheight
            selections = True
        elif win == self.logpad:
            if self.logpad is None:
                return False
            cypos = self.logpadypos
            cxpos = self.logpadxpos
            cheight = self.logpadheight
            # We do not care about selection
            selections = False
        else:
            return Retval.NOMATCH

        cmaxy = self.maxy
        cmaxx = self.maxx
        cyoffset = self.yoffset
        ypos = y - cypos
        xpos = x - cxpos

        # if bstate == curses.BUTTON1_PRESSED:
        # Here goes handling of dragging scrollbars
        if bstate == curses.BUTTON1_DOUBLE_CLICKED and selections:
            # double-clicks on list items
            if activatedfun is not None \
                    and cypos <= y < min(cheight + cypos, cmaxy) and cxpos <= x < cmaxx:
                # We want to move the cursor here,
                # if "here" is a valid line
                try:
                    selected = sorted_list[ypos + cyoffset]
                except IndexError:
                    return Retval.NOMATCH
                self.select(selected)
                self.curypos = ypos
                self.reselect_uid()

                if deep_get(selected, DictPath("ref")):
                    if extraref is not None:
                        view = deep_get(selected, DictPath(extraref), self.view)

                        on_activation = copy.deepcopy(self.on_activation)
                        kind = deep_get(on_activation, DictPath("kind"), view)
                        on_activation.pop("kind", None)
                        if data is not None:
                            _retval = activatedfun(stdscr=self.stdscr,
                                                   obj=deep_get(selected, DictPath("ref")),
                                                   kind=kind, info=data, **on_activation)
                        else:
                            _retval = activatedfun(stdscr=self.stdscr,
                                                   obj=deep_get(selected, DictPath("ref")),
                                                   kind=kind, **on_activation)
                    else:
                        on_activation = copy.deepcopy(self.on_activation)
                        kind = deep_get(on_activation, DictPath("kind"), self.view)
                        on_activation.pop("kind", None)
                        _retval = activatedfun(stdscr=self.stdscr,
                                               obj=deep_get(selected, DictPath("ref")),
                                               kind=kind, **on_activation)
                    if _retval is not None:
                        self.force_refresh()
                    return _retval
        # pylint: disable-next=too-many-nested-blocks
        elif bstate == curses.BUTTON1_CLICKED:
            # clicks on list items
            if cypos <= y < min(cheight + cypos, cmaxy) and cxpos <= x < cmaxx and selections:
                selected = self.get_selected()

                try:
                    here = sorted_list[ypos + cyoffset]
                    new_here = sorted_list[ypos + self.yoffset]
                except IndexError:
                    return Retval.NOMATCH

                # If we are clicking on something that is not selected
                # (or if nothing is selected), move here.
                if selected is None or here is None or selected != here:
                    self.select(new_here)
                    self.curypos = ypos
                    self.reselect_uid()
                else:
                    # If we click an already selected item we open it
                    if deep_get(selected, DictPath("ref")) and activatedfun:
                        self.force_update()
                        if extraref:
                            view = deep_get(selected, DictPath(extraref), self.view)

                            on_activation = copy.deepcopy(self.on_activation)
                            kind = deep_get(on_activation, DictPath("kind"), view)
                            on_activation.pop("kind", None)
                            if data is not None:
                                _retval = activatedfun(stdscr=self.stdscr,
                                                       obj=deep_get(selected, DictPath("ref")),
                                                       kind=kind, info=data, **on_activation)
                            else:
                                _retval = activatedfun(stdscr=self.stdscr,
                                                       obj=deep_get(selected, DictPath("ref")),
                                                       kind=kind, **on_activation)
                        else:
                            on_activation = copy.deepcopy(self.on_activation)
                            kind = deep_get(on_activation, DictPath("kind"), self.view)
                            on_activation.pop("kind", None)
                            _retval = activatedfun(stdscr=self.stdscr,
                                                   obj=deep_get(selected, DictPath("ref")),
                                                   kind=kind, **on_activation)
                        if _retval is not None:
                            self.force_refresh()
                        return _retval
            # clicks on the vertical scrollbar
            elif (y, x) == (self.upperarrow):
                if win == self.listpad:
                    self.move_cur_with_offset(-1)
                else:
                    self.move_yoffset_rel(-1)
            elif (y, x) == (self.lowerarrow):
                if win == self.listpad:
                    self.move_cur_with_offset(1)
                else:
                    self.move_yoffset_rel(1)
            elif x == self.upperarrow[1]:
                if self.upperarrow[0] < y < self.lowerarrow[0]:
                    # Do not count the arrows
                    total = self.lowerarrow[0] - self.upperarrow[0] - 2
                    # Y-position on the bar
                    ypos = y - self.upperarrow[0] - 1
                    # moveoffset
                    moveoffset = int((ypos / total) * self.listpadheight)
                    # start by moving the cursor & offset to 0
                    # that way we can do an relative move
                    self.move_cur_abs(0)
                    self.move_cur_with_offset(moveoffset)
            # clicks on the horizontal scrollbar
            elif (y, x) == (self.leftarrow):
                self.move_xoffset_rel(-1)
            elif (y, x) == (self.rightarrow):
                self.move_xoffset_rel(1)
            elif y == self.leftarrow[0]:
                if self.leftarrow[1] < x < self.rightarrow[1]:
                    # Do not count the arrows
                    total = self.rightarrow[1] - self.leftarrow[1] - 2
                    # X-position on the bar
                    xpos = x - self.leftarrow[1] - 1
                    move = int(self.maxxoffset * (xpos / total))
                    self.move_xoffset_abs(move)
        elif bstate == curses.BUTTON2_CLICKED:
            # Middle button
            pass
        elif bstate == curses.BUTTON3_CLICKED:
            # Right button
            pass
        elif CursesConfiguration.mousescroll_enable \
                and bstate == CursesConfiguration.mousescroll_up:
            # Scroll wheel up
            if self.listpad:
                self.move_cur_with_offset(-5)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(-5)
            return Retval.MATCH
        elif CursesConfiguration.mousescroll_enable \
                and bstate == CursesConfiguration.mousescroll_down:
            if self.listpad:
                self.move_cur_with_offset(5)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(5)
            return Retval.MATCH

        return Retval.NOMATCH

    def enter_handler(self, **kwargs: Any) -> Retval:
        """
        Handle activation.

            Parameters:
                **kwargs (dict[str, Any]): Keyword arguments
                    activatedfun (Callable): The function to call on activation
                    extraref (str): An alternate view reference: This should probably be redesigned
                    data (bool): FIXME
            Returns:
                (Retval): The return value
        """
        activatedfun: Callable | None = deep_get(kwargs, DictPath("activatedfun"))
        extraref: str | None = deep_get(kwargs, DictPath("extraref"))
        data: bool | None = deep_get(kwargs, DictPath("data"))
        selected = self.get_selected()

        if activatedfun and deep_get(selected, DictPath("ref")):
            if extraref:
                view = deep_get(selected, DictPath(extraref), self.view)

                on_activation = copy.deepcopy(self.on_activation)
                kind = deep_get(on_activation, DictPath("kind"), view)
                on_activation.pop("kind", None)
                if data is not None:
                    _retval = activatedfun(stdscr=self.stdscr,
                                           obj=deep_get(selected, DictPath("ref")),
                                           kind=kind, info=data, **on_activation)
                else:
                    _retval = activatedfun(stdscr=self.stdscr,
                                           obj=deep_get(selected, DictPath("ref")),
                                           kind=kind, **on_activation)
            else:
                on_activation = copy.deepcopy(self.on_activation)
                kind = deep_get(on_activation, DictPath("kind"), self.view)
                on_activation.pop("kind", None)
                _retval = activatedfun(stdscr=self.stdscr,
                                       obj=deep_get(selected, DictPath("ref")),
                                       kind=kind, **on_activation)
            if _retval is not None:
                self.force_refresh()
            return _retval

        return Retval.NOMATCH

    annotation_headers: ClassVar[tuple[str, ...]] = ("Annotation:", "Value:")

    label_headers: ClassVar[tuple[str, ...]] = ("Label:", "Value:")

    # pylint: disable-next=too-many-return-statements,too-many-statements,too-many-branches
    def generic_keycheck(self, c: int) -> Retval:
        """
        Process key presses, window resize events, and mouse events.

            Parameters:
                c (int): The key press.
            Returns:
                (Retval): The return value:
                          Retval.NOMATCH if the key press was not handled,
                          Retval.MATCH if the key press was handled,
                          Retval.RETURNONE to return one level up.
        """
        # No input
        if c == -1:
            return Retval.NOMATCH

        # We got some type of keypress; postpone idle
        self.last_action = datetime.now(UTC)

        if c == curses.KEY_RESIZE:
            self.resize_window()
            return Retval.MATCH
        if c == 27:  # ESCAPE
            del self
            return Retval.RETURNONE
        if c == curses.KEY_MOUSE:
            return self.handle_mouse_events(cast(curses.window, self.listpad),
                                            self.sorted_list, activatedfun=self.activatedfun,
                                            extraref=self.extraref, data=self.data)
        if c in (curses.KEY_ENTER, 10, 13) and self.activatedfun is not None:
            return self.enter_handler(activatedfun=self.activatedfun,
                                      extraref=self.extraref, data=self.data)
        if c == ord("M"):
            # Toggle mouse support on/off to allow for copy'n'paste
            if get_mousemask() == 0:
                set_mousemask(-1)
            else:
                set_mousemask(0)
            if self.bottom_statusbar is not None:
                self.bottom_statusbar.erase()
            self.refresh_all()
            return Retval.MATCH
        if c == ord("") or c == ord(""):
            curses.endwin()
            sys.exit()
        if c == curses.KEY_F1 or c == ord("H"):
            if self.helptext is not None:
                windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                             items=self.helptext, title="Help", cursor=False)
            self.refresh_all()
            return Retval.MATCH
        if c == curses.KEY_F12:
            if CursesConfiguration.abouttext is not None:
                items = []
                for line in CursesConfiguration.abouttext:
                    items.append({"lineattrs": WidgetLineAttrs.NORMAL,
                                  "columns": [line], "retval": None})
                windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                             items=items, title="About", cursor=False)
            self.refresh_all()
            return Retval.MATCH
        if c == curses.KEY_F5:
            # We need to rate limit this somehow
            self.force_update()
            self.update_forced = True
            self.force_idle()
            return Retval.MATCH
        if c == ord("a") and self.annotations:
            title = "Annotations:"

            windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                         items=self.annotations, headers=self.annotation_headers,
                         title=title, cursor=False)

            self.refresh_all()
            return Retval.MATCH
        if c == ord("l") and self.labels:
            title = "Labels:"

            windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                         items=self.labels, headers=self.label_headers,
                         title=title, cursor=False)

            self.refresh_all()
            return Retval.MATCH

        # Everything below is either for logpads or listpads;
        # leave the shortcuts unused for cases where they're not needed
        if self.listpad is None and self.logpad is None:
            return Retval.NOMATCH

        if c == ord("r") and self.listpad and self.reversible:
            # Reverse the sort order
            self.sortorder_reverse = not self.sortorder_reverse
            self.sort_triggered = True
            return Retval.MATCH
        if c == curses.KEY_SLEFT:
            # For listpads we switch sort column with this;
            # for logpads we move half a page left/right
            if self.listpad and self.sortable:
                self.prev_sortcolumn()
            elif self.logpad and not self.continuous_log:
                self.move_xoffset_rel(-(self.logpadminwidth // 2))
            return Retval.MATCH
        if c == curses.KEY_SRIGHT:
            if self.listpad and self.sortable:
                self.next_sortcolumn()
            elif self.logpad and not self.continuous_log:
                self.move_xoffset_rel(self.logpadminwidth // 2)
            return Retval.MATCH
        if c == curses.KEY_UP:
            if self.listpad:
                self.move_cur_with_offset(-1)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(-1)
            return Retval.MATCH
        if c == curses.KEY_DOWN:
            if self.listpad:
                self.move_cur_with_offset(1)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(1)
            return Retval.MATCH
        if c == curses.KEY_LEFT:
            if self.logpad and self.continuous_log:
                return Retval.MATCH

            self.move_xoffset_rel(-1)
            return Retval.MATCH
        if c == curses.KEY_RIGHT:
            if self.logpad and self.continuous_log:
                return Retval.MATCH

            self.move_xoffset_rel(1)
            return Retval.MATCH
        if c == curses.KEY_HOME:
            if self.logpad and self.continuous_log:
                return Retval.MATCH

            self.move_xoffset_abs(0)
            return Retval.MATCH
        if c == curses.KEY_END:
            if self.logpad and self.continuous_log:
                return Retval.MATCH

            self.move_xoffset_abs(-1)
            return Retval.MATCH
        if c == curses.KEY_SHOME:
            if self.logpad:
                if self.continuous_log:
                    return Retval.MATCH
                self.move_yoffset_abs(0)
            elif self.listpad:
                self.move_cur_abs(0)
            return Retval.MATCH
        if c == curses.KEY_SEND:
            if self.logpad:
                if self.continuous_log:
                    return Retval.MATCH
                self.move_yoffset_abs(-1)
            elif self.listpad:
                self.move_cur_abs(-1)
            return Retval.MATCH
        if c == curses.KEY_PPAGE:
            if self.listpad:
                self.move_cur_with_offset(-10)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(-(self.logpadheight - 2))
            return Retval.MATCH
        if c == curses.KEY_NPAGE:
            if self.listpad:
                self.move_cur_with_offset(10)
            elif self.logpad and not self.continuous_log:
                self.move_yoffset_rel(self.logpadheight - 2)
            return Retval.MATCH
        if c == ord("\t"):
            if self.listpad:
                self.next_by_sortkey(self.info)
            elif self.logpad and not self.continuous_log:
                self.next_line_by_severity(self.severities, self.timestamps)
            return Retval.MATCH
        if c == curses.KEY_BTAB:
            if self.listpad:
                self.prev_by_sortkey(self.info)
            elif self.logpad and not self.continuous_log:
                self.prev_line_by_severity(self.severities, self.timestamps)
            return Retval.MATCH
        if c == ord("§"):
            # For listpads this jumps to the next column
            if self.listpad:
                # In case the list empty for some reason
                tabstop = 0
                curxoffset = self.xoffset
                # Find next tabstop
                for tabstop in self.tabstops:
                    if curxoffset < tabstop:
                        if tabstop <= self.maxxoffset:
                            self.move_xoffset_abs(tabstop)
                        break
            return Retval.MATCH
        if c == ord("½"):
            # For listpads this jumps to the previous column
            if self.listpad:
                # In case the list empty for some reason
                tabstop = 0
                curxoffset = self.xoffset
                # Find previous tabstop
                for tabstop in reversed(self.tabstops):
                    if curxoffset > tabstop:
                        self.move_xoffset_abs(tabstop)
                        break
            return Retval.MATCH
        if c == ord("") or c == ord("/"):
            if self.listpad:
                if self.listpadheight < 2:
                    return Retval.MATCH

                search_title = f"Search in “{self.sortcolumn}“: "
                if not (searchkey := inputbox(self.stdscr, title=search_title)):
                    return Retval.MATCH

                self.find_next_by_sortkey(self.info, searchkey)
                self.searchkey = searchkey
            elif self.logpad:
                if self.maxyoffset == 0 or self.continuous_log:
                    return Retval.MATCH

                self.refresh = True
                search_title = "Find: "
                if not (searchkey := inputbox(self.stdscr, title=search_title)):
                    self.match_index = None
                    self.search_matches.clear()
                    return Retval.MATCH

                self.find_all_matches_by_searchkey(self.messages, searchkey)
                self.find_next_match()
            return Retval.MATCH
        if c == ord("?"):
            self.search_matches.clear()

            if self.listpad:
                if self.listpadheight < 2:
                    return Retval.MATCH

                search_title = f"Search in “{self.sortcolumn}“: "
                if not (searchkey := inputbox(self.stdscr, title=search_title)):
                    return Retval.MATCH

                self.find_prev_by_sortkey(self.info, searchkey)
                self.searchkey = searchkey
            elif self.logpad:
                if self.maxyoffset == 0 or self.continuous_log:
                    return Retval.MATCH

                self.refresh = True
                search_title = "Find: "
                if not (searchkey := inputbox(self.stdscr, title=search_title)):
                    self.match_index = None
                    self.search_matches.clear()
                    return Retval.MATCH

                self.find_all_matches_by_searchkey(self.messages, searchkey)
                self.find_next_match()
            return Retval.MATCH
        if c == ord("n"):
            if self.listpad:
                if self.listpadheight < 2:
                    return Retval.MATCH

                if not self.searchkey:
                    return Retval.MATCH

                self.find_next_by_sortkey(self.info, self.searchkey)
            elif self.logpad:
                if self.maxyoffset == 0 or self.continuous_log or not self.search_matches:
                    return Retval.MATCH

                self.refresh = True
                self.find_next_match()
            return Retval.MATCH
        if c == ord("p"):
            if self.listpad:
                if self.listpadheight < 2:
                    return Retval.MATCH

                if not self.searchkey:
                    return Retval.MATCH

                self.find_prev_by_sortkey(self.info, self.searchkey)
            elif self.logpad:
                if not self.maxyoffset or self.continuous_log or not self.search_matches:
                    return Retval.MATCH

                self.refresh = True
                self.find_prev_match()
            return Retval.MATCH

        # Nothing good enough for you, eh?
        return Retval.NOMATCH

    # Shortcuts used in most view
    def __exit_program(self, **kwargs: Any) -> NoReturn:
        retval = deep_get(kwargs, DictPath("retval"))

        curses.endwin()
        sys.exit(retval)

    # pylint: disable-next=unused-argument
    def __refresh_information(self, **kwargs: Any) -> tuple[Retval, dict]:
        # XXX: We need to rate limit this somehow
        self.force_update()
        return Retval.MATCH, {}

    def __select_menu(self, **kwargs: Any) -> tuple[Retval, dict]:
        refresh_apis = deep_get(kwargs, DictPath("refresh_apis"), "none")
        selectwindow = deep_get(kwargs, DictPath("selectwindow"))

        retval = selectwindow(self, refresh_apis=refresh_apis)
        if retval == Retval.RETURNFULL:
            return retval, {}
        self.refresh_all()
        return retval, {}

    # pylint: disable-next=unused-argument
    def __show_about(self, **kwargs: Any) -> tuple[Retval, dict]:
        if CursesConfiguration.abouttext is not None:
            items = []
            for line in CursesConfiguration.abouttext:
                items.append({"lineattrs": WidgetLineAttrs.NORMAL,
                              "columns": [line], "retval": None})
            windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                         items=items, title="About", cursor=False)
        self.refresh_all()
        return Retval.MATCH, {}

    def __show_help(self, **kwargs: Any) -> tuple[Retval, dict]:
        helptext = deep_get(kwargs, DictPath("helptext"))

        windowwidget(self.stdscr, self.maxy, self.maxx, self.maxy // 2, self.maxx // 2,
                     items=helptext, title="Help", cursor=False)
        self.refresh_all()
        return Retval.MATCH, {}

    # pylint: disable-next=unused-argument
    def __toggle_mouse(self, **kwargs: Any) -> tuple[Retval, dict]:
        # Toggle mouse support on/off to allow for copy'n'paste
        if get_mousemask() == 0:
            set_mousemask(-1)
        else:
            set_mousemask(0)
        if self.bottom_statusbar is not None:
            self.bottom_statusbar.erase()
        self.refresh_all()
        return Retval.MATCH, {}

    # pylint: disable-next=unused-argument
    def __toggle_borders(self, **kwargs: Any) -> tuple[Retval, dict]:
        self.toggle_borders()
        self.refresh_all()
        self.force_update()
        return Retval.MATCH, {}

    # pylint: disable-next=too-many-locals
    def generate_helptext(self, shortcuts: dict, **kwargs: Any) -> list[dict]:
        """
        Generate helptexts to use with generic_inputhandler().

            Parameters:
                shortcuts (dict): A dict of shortcuts
                kwargs (dict): Additional parameters
            Returns:
                ([dict]): A list of dicts formatted for passing to windowwidget()
        """
        read_only_mode = deep_get(kwargs, DictPath("read_only"), False)
        subview = deep_get(kwargs, DictPath("subview"), False)

        # There are (up to) four helptext groups:
        # Global
        # Global F-keys
        # Command
        # Navigation keys
        helptext_groups: list[list] = [[], [], [], []]

        for shortcut_name, shortcut_data in shortcuts.items():
            read_only = deep_get(shortcut_data, DictPath("read_only"), False)
            if read_only_mode and not read_only:
                continue

            helptext_group = deep_get(shortcut_data, DictPath("helpgroup"))
            if helptext_group is None:
                raise ValueError(f"The shortcut {shortcut_name} has no helpgroup; "
                                 "this is a programming error.")
            if (tmp := deep_get(shortcut_data, DictPath("helptext"))) is None:
                raise ValueError(f"The shortcut {shortcut_name} has no helptext; "
                                 "this is a programming error.")

            helptext_groups[helptext_group].append(tmp)

        helptext = []
        if subview:
            helptext.append(("", ""))

        first = True
        for helptexts in helptext_groups:
            if not helptexts:
                continue
            if not first:
                helptext.append(("", ""))
            for key, description in helptexts:
                helptext.append((key, description))
            first = False

        return format_helptext(helptext)

    # pylint: disable-next=too-many-locals,too-many-branches
    def generic_inputhandler(self, shortcuts: dict, **kwargs: Any) -> tuple[Retval, dict]:
        """
        Generic inputhandler for views.

            Parameters:
                shortcuts (dict): View-specific shortcuts
                kwargs (dict): Additional parameters
            Returns:
                (Retval, dict): retval, return_args
        """
        __common_shortcuts = {
            "Exit program": {
                "shortcut": [ord(""), ord("")],
                "helptext": ("[Ctrl] + X", "Exit program"),
                "helpgroup": 0,
                "action": "key_callback",
                "action_call": self.__exit_program,
                "action_args": {
                    "retval": 0,
                }
            },
            "Refresh information": {
                "shortcut": [curses.KEY_F5],
                "helptext": ("[F5]", "Refresh information"),
                "helpgroup": 1,
                "action": "key_callback",
                "action_call": self.__refresh_information,
            },
            "Show information about the program": {
                "shortcut": [curses.KEY_F12],
                "helptext": ("[F12]", "Show information about the program"),
                "helpgroup": 1,
                "action": "key_callback",
                "action_call": self.__show_about,
            },
            "Show this helptext": {
                "shortcut": [curses.KEY_F1, ord("H")],
                "helptext": ("[F1] / [Shift] + H", "Show this helptext"),
                "helpgroup": 1,
                "action": "key_callback",
                "action_call": self.__show_help,
            },
            "Switch main view": {
                "shortcut": [curses.KEY_F2],
                "helptext": ("[F2]", "Switch main view"),
                "helpgroup": 1,
                "action": "key_callback",
                "action_call": self.__select_menu,
            },
            "Switch main view (recheck available API resources)": {
                "shortcut": [curses.KEY_F3],
                "helptext": ("[F3]", "Switch main view (recheck available API resources)"),
                "helpgroup": 1,
                "action": "key_callback",
                "action_call": self.__select_menu,
                "action_args": {
                    "refresh_apis": "all",
                }
            },
            "Toggle mouse on/off": {
                "shortcut": [ord("M")],
                "helptext": ("[Shift] + M", "Toggle mouse on/off"),
                "helpgroup": 0,
                "action": "key_callback",
                "action_call": self.__toggle_mouse,
            },
            "Toggle borders": {
                "shortcut": [ord("B")],
                "helptext": ("[Shift] + B", "Toggle borders on/off"),
                "helpgroup": 0,
                "action": "key_callback",
                "action_call": self.__toggle_borders,
            },
        }

        self.stdscr.timeout(100)
        c = self.stdscr.getch()
        altkey = False

        # Default return value if we do not manage to match anything
        retval = Retval.NOMATCH
        return_data = {
            "keypress": c
        }

        if c == curses.KEY_RESIZE:
            self.resize_window()
            return Retval.MATCH, return_data

        if c == 27:  # Either ESCAPE or ALT+<key>
            self.stdscr.nodelay(True)
            c2 = self.stdscr.getch()
            self.stdscr.nodelay(False)
            # No additional key; this was a real ESCAPE press
            if c2 == -1:
                del self
                return Retval.RETURNONE, return_data
            # Additional key pressed; this is ALT+<key>
            altkey = True
            c = c2

        if c == curses.KEY_MOUSE:
            return self.handle_mouse_events(cast(curses.window, self.listpad),
                                            self.sorted_list, activatedfun=self.activatedfun,
                                            extraref=self.extraref, data=self.data), return_data

        if c in (curses.KEY_ENTER, 10, 13) and self.activatedfun is not None:
            return self.enter_handler(activatedfun=self.activatedfun,
                                      extraref=self.extraref, data=self.data), return_data

        # First generate a list of all the shortcuts we should check
        __shortcuts = {}

        # We *always* add the shortcut to exit the program
        __shortcuts["Exit program"] = __common_shortcuts["Exit program"]

        # Now iterate the list of common shortcuts in the shortcuts dict
        for shortcut_name in deep_get(shortcuts, DictPath("__common_shortcuts"), []):
            if shortcut_name not in __common_shortcuts:
                raise ValueError(f"Common shortcut {shortcut_name} is not defined in "
                                 "__common_shortcuts; this is a programming error.")
            __shortcuts[shortcut_name] = deep_get(__common_shortcuts, DictPath(shortcut_name))

        # Finally add all the remaining shortcuts
        for shortcut_name, shortcut_data in shortcuts.items():
            # We've already dealt with this
            if shortcut_name == "__common_shortcuts":
                continue
            __shortcuts[shortcut_name] = shortcut_data

        # Now generate helptext
        helptext = self.generate_helptext(__shortcuts, **kwargs)

        for shortcut_name, shortcut_data in __shortcuts.items():
            keys = deep_get(shortcut_data, DictPath("shortcut"), [])
            # Currently this is only used for [Alt]
            modifier = deep_get(shortcut_data, DictPath("modifier"), "")

            if isinstance(keys, int):
                keys = [keys]

            if c in keys:
                if altkey and modifier.lower() != "alt" \
                   or not altkey and modifier.lower() == "alt":
                    continue

                action = deep_get(shortcut_data, DictPath("action"))
                action_call = deep_get(shortcut_data, DictPath("action_call"))
                _action_args = deep_get(shortcut_data, DictPath("action_args"), {})
                action_args: dict = {**kwargs, **_action_args}
                action_args["__keypress"] = c
                action_args["helptext"] = helptext
                if action == "key_callback":
                    return action_call(**action_args)

        return retval, return_data
