# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Setup a shortcut mapping with helptext.
"""

import curses
import sys
from collections.abc import Callable

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


key_mappings: dict[str, list[int]] = {
    "f1": [curses.KEY_F1],
    "f2": [curses.KEY_F2],
    "f3": [curses.KEY_F3],
    "f4": [curses.KEY_F4],
    "f5": [curses.KEY_F5],
    "f6": [curses.KEY_F6],
    "f7": [curses.KEY_F7],
    "f8": [curses.KEY_F8],
    "f9": [curses.KEY_F9],
    "f10": [curses.KEY_F10],
    "f11": [curses.KEY_F11],
    "f12": [curses.KEY_F12],
    "f13": [curses.KEY_F13],
    "f14": [curses.KEY_F14],
    "f15": [curses.KEY_F15],
    "f16": [curses.KEY_F16],
    "f17": [curses.KEY_F17],
    "f18": [curses.KEY_F18],
    "f19": [curses.KEY_F19],
    "f20": [curses.KEY_F20],
    "f21": [curses.KEY_F21],
    "f22": [curses.KEY_F22],
    "f23": [curses.KEY_F23],
    "f24": [curses.KEY_F24],
}


# pylint: disable-next=too-many-branches
def map_key(view_file: str, shortcut: str, activatedfun: Callable | None,
            key: str, modifier: str) -> tuple[list[int], str]:
    """
    Setup a shortcut mapping and return the key-code(s) + helptext.

        Parameters:
            view_file (str): The path to the view-file (used for error messages)
            shortcut (str): The shortcut description (used for error messages)
            activatedfun (Callable): The function to call upon activation;
                                     used to double-check whether the default shortcut
                                     for "enter" has been disabled.
            key (str): They base key
            modifier (str): The modifier (""/"shift"/"ctrl")
        Returns:
            ((int | [int], str)):
                ([int]): The shortcut key(s)
                (str): The helptext
    """
    if modifier and modifier not in ("ctrl", "shift"):
        sys.exit(f"View-file {view_file} is invalid: "
                 f"unknown modifier {modifier}; valid modifiers are shift, ctrl; aborting")

    if key in ("f1", "f2", "f3", "f4", "f5", "f6",
               "f7", "f8", "f9", "f10", "f11", "f12") and modifier in ("", "shift"):
        if modifier == "shift":
            key_: str = key[0] + str(int(key[1:]) + 12)
            num = int(key[1:]) + 12
            shortcut_key: list[int] = deep_get(key_mappings, DictPath(key_))
            help_key: str = f"[Shift] + [{key.upper()}] / [{key[0].upper()}{num}]"
        else:
            shortcut_key = deep_get(key_mappings, DictPath(key))
            help_key = f"[{key.upper()}]"
    elif key in ("f13", "f14", "f15", "f16", "f17", "f18",
                 "f19", "f20", "f21", "f22", "f23", "f24") and not modifier:
        num = int(key[1:])
        key_ = key[0] + str(num)
        shortcut_key = deep_get(key_mappings, DictPath(key_))
        help_key = f"[Shift] + [{key[0].upper()}{num - 12}] / [{key.upper()}]"
    elif key in ("enter", "return"):
        if modifier or activatedfun is None:
            help_key = "[Enter]"
            shortcut_key = [curses.KEY_ENTER, 10, 13]
        else:
            sys.exit(f"View-file “{view_file}“ is invalid: the listview shortcut “{shortcut}“"
                     " uses “enter“ as key; this conflicts with "
                     "built-in shortcut for “on_activation“.")
    elif modifier:
        if modifier == "shift":
            help_key = f"[Shift] + {key.upper()}"
            shortcut_key = [ord(key.upper())]
        elif modifier == "ctrl":
            help_key = f"[Ctrl] + {key.upper()}"
            shortcut_key = [ord(key) - 96]
        else:  # pragma: no cover
            # This shouldn't be necessary since we check this at the beginning of the function,
            # but pylint complains otherwise.
            sys.exit(f"View-file {view_file} is invalid: "
                     f"unknown modifier {modifier}; valid modifiers are shift, ctrl; aborting")
    elif len(key) == 1:
        help_key = f"{key.upper()}"
        shortcut_key = [ord(key)]
    else:
        sys.exit(f"View-file {view_file} is invalid: "
                 f"unknown key {key}; aborting")

    return shortcut_key, help_key
