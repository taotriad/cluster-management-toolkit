# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert ThemeAttr to a tuple with its corresponding Curses representation.
"""

import curses

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


# pylint: disable-next=too-many-branches
def themeattr_to_curses(themeattr: ThemeAttr, selected: bool = False) -> tuple[int, int]:
    """
    Given a themeattr returns a tuple with curses color + curses attributes.

        Parameters:
            themeattr (ThemeAttr): The ThemeAttr to convert
            selected (bool): [optional] True is selected, False otherwise
        Returns:
            (int, int):
                (int): A curses color
                (int): Curses attributes
    """
    context, key = themeattr
    tmp_attr = deep_get(ThemeStrConfiguration.theme, DictPath(f"{context}#{key}"))

    if tmp_attr is None:
        errmsg = [
            [("Could not find the tuple (", "default"),
             (f"{context}", "argument"),
             (", ", "default"),
             (f"{key}", "argument"),
             (") in themefile ", "default"),
             (f"{ThemeStrConfiguration.themefile}", "path")],
            [("Using (", "default"),
             ("main", "argument"),
             (", ", "default"),
             ("default", "argument"),
             (") as fallback.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        tmp_attr = deep_get(ThemeStrConfiguration.theme, DictPath("main#default"))

    if isinstance(tmp_attr, dict):
        if selected:
            attr = tmp_attr["selected"]
        else:
            attr = tmp_attr["unselected"]
    else:
        attr = tmp_attr

    if isinstance(attr, list):
        col, attr = attr
    else:
        col = attr
        attr = "normal"

    if isinstance(attr, str):
        attr = [attr]
    else:
        attr = list(attr)

    tmp = 0

    for item in attr:
        if not isinstance(item, str):
            errmsg = [
                [("Invalid text attribute used in themefile ", "default"),
                 (f"{ThemeStrConfiguration.themefile}", "path"),
                 ("; attribute has to be a string and one of:", "default")],
                [("“", "default"),
                 ("dim", "argument"),
                 ("“, “", "default"),
                 ("normal", "argument"),
                 ("“, “", "default"),
                 ("bold", "argument"),
                 ("“, “", "default"),
                 ("underline", "argument"),
                 ("“.", "default")],
                [("Using “", "default"),
                 ("normal", "argument"),
                 ("“ as fallback.", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            item = "normal"
        if item == "dim":
            tmp |= curses.A_DIM
        elif item == "normal":
            tmp |= curses.A_NORMAL
        elif item == "bold":
            tmp |= curses.A_BOLD
        elif item == "italics":
            tmp |= curses.A_ITALIC
        elif item == "underline":
            tmp |= curses.A_UNDERLINE
        else:
            errmsg = [
                [("Invalid text attribute “", "default"),
                 (f"{item}", "emphasis"),
                 ("“ used in themefile ", "default"),
                 (f"{ThemeStrConfiguration.themefile}", "path"),
                 ("; attribute has to be one of:", "default")],
                [("“", "default"),
                 ("dim", "argument"),
                 ("“, “", "default"),
                 ("normal", "argument"),
                 ("“, “", "default"),
                 ("bold", "argument"),
                 ("“, “", "default"),
                 ("underline", "argument"),
                 ("“.", "default")],
                [("Using “", "default"),
                 ("normal", "argument"),
                 ("“ as fallback.", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            tmp |= curses.A_NORMAL
    curses_attrs = tmp

    curses_col = ThemeStrConfiguration.color[col][selected]
    if curses_col is None:
        errmsg = [
            [("Non-existing (color, selected) tuple ", "default")],
            [(f"{col}", "argument")],
            [(", ", "default")],
            [(f"{selected}", "argument")],
            [(").", "default")],
            [("Using first defined tuple as fallback.", "default")],
        ]
        curses_col = ThemeStrConfiguration.color[0][selected]
    return curses_col, curses_attrs
