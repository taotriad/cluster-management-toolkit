# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A logpad for strings with embedded newlines.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def logpad_msg_getter(obj: dict, **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Get a string with embedded newlines, split it into a list of ThemeArrays.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): Path to the string
        Returns:
            ([themearray]): A list of themearrays
    """
    messages: list[list[ThemeRef | ThemeStr]] = []

    path = deep_get(kwargs, DictPath("path"))
    tmp = deep_get(obj, DictPath(path), "")

    for line in split_msg(tmp):
        messages.append([ThemeStr(f"{line}", ThemeAttr("main", "default"))])

    return messages
