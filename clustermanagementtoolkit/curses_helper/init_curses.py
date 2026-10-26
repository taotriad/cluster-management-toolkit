# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Initialise the curses UI.
"""

import curses
import os
import re
import sys

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemestr_join_list

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


color_map: dict[str, int] = {
    "black": curses.COLOR_BLACK,
    "red": curses.COLOR_RED,
    "green": curses.COLOR_GREEN,
    "yellow": curses.COLOR_YELLOW,
    "blue": curses.COLOR_BLUE,
    "magenta": curses.COLOR_MAGENTA,
    "cyan": curses.COLOR_CYAN,
    "white": curses.COLOR_WHITE,
}


def __convert_color_pair(color_pair: tuple[tuple[str, str], tuple[str, str]]) -> tuple[int, int]:
    fg, bg = color_pair

    curses_fg = __color_name_to_curses_color(fg, "foreground")
    curses_bg = __color_name_to_curses_color(bg, "background")

    return (curses_fg, curses_bg)


def __color_name_to_curses_color(color: tuple[str, str], color_type: str) -> int:
    try:
        col, attr = color
    except (TypeError, ValueError):
        errmsg = [
            [("Invalid color pair used in theme ", "warning"),
             (f"{ThemeStrConfiguration.themefile}", "path"),
             (":", "warning")],
            [("color = ", "default"),
             (f"{color}", "argument"),
             (" (type: ", "default"),
             (f"{type(color)}", "argument"),
             (", expected: ", "default"),
             ("(str, str)", "argument")],
            [("Defaulting to ", "default"),
             ("(white, normal)", "argument"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.INFO, msg=unformatted_msg, messages=formatted_msg)

        col = "white"
        attr = "normal"

    if not isinstance(attr, str) or attr not in ("normal", "bright"):
        tmp_attr_list = ansithemestr_join_list(("normal", "bright"),
                                               formatting="argument",
                                               separator=ANSIThemeStr(", ", "separator"))
        attr_list = ANSIThemeStr.ansithemearray_to_tuplelist(tmp_attr_list)
        errmsg = [
            [("Invalid color attribute used in theme ", "warning"),
             (f"{ThemeStrConfiguration.themefile}", "path"),
             (":", "warning")],
            [("attr = ", "default"),
             (f"{attr}", "argument"),
             (" (type: ", "default"),
             (f"{type(attr)}", "argument"),
             (", expected: ", "default"),
             ("str", "argument"),
             (", with attr being one of ", "default")] + attr_list,
            [("Defaulting to ", "default"),
             ("normal", "argument"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)

        attr = "normal"

    if isinstance(col, str):
        col = col.lower()

    if not isinstance(col, str) or col not in color_map:
        tmp_color_list = ansithemestr_join_list(list(color_map),
                                                formatting="argument",
                                                separator=ANSIThemeStr(", ", "separator"))
        color_list = ANSIThemeStr.ansithemearray_to_tuplelist(tmp_color_list)
        errmsg = [
            [(f"Invalid {color_type} color used in theme ", "warning"),
             (f"{ThemeStrConfiguration.themefile}", "path"),
             (":", "warning")],
            [("color = ", "default"),
             (f"{col}", "argument"),
             (" (type: ", "default"),
             (f"{type(col)}", "argument"),
             (", expected: ", "default"),
             ("str", "argument"),
             (", with color being one of ", "default")] + color_list,
            [("Defaulting to ", "default"),
             ("white", "argument"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)

        col = "white"

    if attr == "bright":
        curses_attr = 8
    else:
        curses_attr = 0

    curses_color = deep_get(color_map, DictPath(col))

    return curses_color + curses_attr


def __init_pair(pair: str, color_pair: tuple[int, int], color_nr: int) -> None:
    if not curses.has_colors():  # pragma: no cover
        term = os.getenv("TERM", "<unknown>")
        sys.exit(f"Error: Your terminal environment TERM={term} reports that it does not\n"
                 "support colors; at least currently cmu requires color support; exiting.")

    fg, bg = color_pair
    bright_black_remapped = False

    if fg == bg:
        errmsg = [
            [("Themefile ", "error"),
             (f"{ThemeStrConfiguration.themefile}", "path"),
             (" contains a color pair ", "error"),
             (f"{pair}", "argument"),
             (" where fg == bg:", "error")],
            [("fg = ", "default"),
             (f"{fg}", "argument")],
            [("bg = ", "default"),
             (f"{bg}", "argument")],
            [("Defaulting to ", "default"),
             ("white", "argument"),
             (" on ", "default"),
             ("black", "argument"),
             (".", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)

        fg = curses.COLOR_WHITE
        bg = curses.COLOR_BLACK

    try:
        curses.init_pair(color_nr, fg, bg)
    except (curses.error, ValueError) as e:
        re_tmp = re.match(r"^Color number is greater than COLORS-1 \((\d+)\).*", str(e))
        if str(e).startswith("init_pair() returned ERR") or re_tmp:
            mask = 7
            if re_tmp:
                mask = int(re_tmp[1])

            errmsg = [
                [("Initialising color pair ", "warning"),
                 (f"{pair}", "argument"),
                 (" (", "warning"),
                 (f"{fg}", "argument"),
                 (", ", "warning"),
                 (f"{bg}", "argument"),
                 (") failed.", "warning")],
                [("Attempting to limit fg & bg to [", "warning"),
                 ("0", "argument"),
                 ("-", "warning"),
                 (f"{mask}", "argument"),
                 ("]", "warning")],
                [("themefile = ", "default"),
                 (f"{ThemeStrConfiguration.themefile}", "path")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)

            # Most likely we failed due to the terminal only
            # supporting colours 0-7. If "bright black" was
            # requested, we need to remap it. Fallback to blue;
            # hopefully there are no cases of bright black on blue.
            fg_old = fg
            if fg & mask == curses.COLOR_BLACK:
                fg = curses.COLOR_BLUE
                bright_black_remapped = True
            if fg & mask == bg & mask:
                errmsg = [
                    [("Initialising color pair ", "error"),
                     (f"{pair}", "argument"),
                     (" (", "warning"),
                     (f"{fg & mask}", "argument"),
                     (", ", "error"),
                     (f"{bg & mask}", "argument"),
                     (") failed; fg == bg (bright black remapped: ", "error"),
                     (f"{bright_black_remapped}", "argument"),
                     (")", "error")],
                    [("themefile = ", "default"),
                     (f"{ThemeStrConfiguration.themefile}", "path")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                raise ValueError(unformatted_msg) from e
            curses.init_pair(color_nr, fg & mask, bg & mask)

            errmsg = [
                [("Remapped the color pair ", "debug"),
                 (f"{pair}", "argument"),
                 (" (", "warning"),
                 (f"{fg_old}", "argument"),
                 (", ", "debug"),
                 (f"{bg}", "argument"),
                 (") to (", "debug"),
                 (f"{fg & mask}", "argument"),
                 (", ", "debug"),
                 (f"{bg & mask}", "argument"),
                 ("; bright black remapped: ", "debug"),
                 (f"{bright_black_remapped}", "argument"),
                 (")", "error")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.DEBUG, msg=unformatted_msg, messages=formatted_msg)
        else:
            raise


def init_curses() -> None:
    """
    Initialise the curses helper; this configures all curses color pairs needed
    for the various ThemeAttrs.
    """
    color_last = 1

    # First we set the colour palette
    for col, curses_col in color_map.items():
        rgb = deep_get(ThemeStrConfiguration.theme, DictPath(f"colors#{col}"))
        if rgb is None:
            continue
        r, g, b = rgb
        try:
            curses.init_color(curses_col, r, g, b)
        except curses.error as e:
            if str(e) == "init_extended_color() returned ERR":
                # Most likely remapping the palette is not supported (16-color xterm?);
                # just ignore the remap attempt
                pass
            else:
                raise

    # Next we need to define all necessary colour pairs;
    # most of them come in selected and unselected variants
    for pair in ThemeStrConfiguration.theme["color_pairs_curses"]:
        if isinstance(ThemeStrConfiguration.theme["color_pairs_curses"][pair], list):
            unselected = \
                __convert_color_pair(ThemeStrConfiguration.theme["color_pairs_curses"][pair])
            selected = unselected
        else:
            # pylint: disable-next=line-too-long
            unselected = __convert_color_pair(ThemeStrConfiguration.theme["color_pairs_curses"][pair]["unselected"])  # noqa: E501
            # pylint: disable-next=line-too-long
            selected = __convert_color_pair(ThemeStrConfiguration.theme["color_pairs_curses"][pair]["selected"])  # noqa: E501

        if unselected not in ThemeStrConfiguration.pairs:
            __init_pair(pair, unselected, color_last)
            ThemeStrConfiguration.pairs[unselected] = curses.color_pair(color_last)
            color_last += 1
        unselected_index = ThemeStrConfiguration.pairs[unselected]
        if selected not in ThemeStrConfiguration.pairs:
            __init_pair(pair, selected, color_last)
            ThemeStrConfiguration.pairs[selected] = curses.color_pair(color_last)
            color_last += 1
        selected_index = ThemeStrConfiguration.pairs[selected]
        ThemeStrConfiguration.color[pair] = (unselected_index, selected_index)
