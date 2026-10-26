# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for version strings.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_compact
from clustermanagementtoolkit.curses_helper import themearray_select


def format_version(items: str | list[str],
                   selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a string, format it as a version.

        Parameters:
            items (str|[str]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []

    if isinstance(items, (int, str, tuple)):
        items = [items]

    item_separator = deep_get(kwargs, DictPath("item_separator"),
                              ThemeRef("separators", "list", selected))

    separators: set = set("+-~.,")

    for item in items:
        if not item:
            continue

        item = str(item)

        tmparray: list[ThemeRef | ThemeStr] = []
        if item.startswith("v"):
            tmparray += [ThemeStr("v", ThemeAttr("types", "version"), selected=selected)]
            item = item[1:]
        for char in item:
            if char in separators:
                tmparray += [ThemeStr(char, ThemeAttr("types", "unit"), selected=selected)]
            else:
                tmparray += [ThemeStr(char, ThemeAttr("types", "numerical"), selected=selected)]
        tmparray = list(themearray_select(themearray_compact(tmparray),
                                          selected=selected, force=True))
        if array:
            item_separator.selected = selected
            array.append(item_separator)
        array += tmparray

    return array
