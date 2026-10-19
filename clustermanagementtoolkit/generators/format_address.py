# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format an address; kept separate from format_address_with_port()
to avoid issues with IPv6-addresses.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.generators_types import FormattingType


# pylint: disable-next=too-many-branches
def format_address(items: str | list[str],
                   selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a list of strings, return them formatted as addresses.

        Parameters:
            items (str|[str]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                formatting (FormattingType): Formatting for the data
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    formatting: FormattingType = deep_get(kwargs, DictPath("formatting"), {})

    if isinstance(items, (str, tuple)):
        items = [items]

    item_separator = deep_get(formatting, DictPath("item_separator"),
                              ThemeRef("separators", "list", selected))

    separator_lookup = {}

    separators = [ThemeRef("separators", "ipv4address", selected),
                  ThemeRef("separators", "ipv6address", selected),
                  ThemeRef("separators", "ipmask", selected)]

    for separator in separators:
        separator_lookup[str(separator)] = separator

    array: list[ThemeRef | ThemeStr] = []

    for item in items:
        if item is None:
            continue
        subnet = False
        _vlist: list[ThemeRef | ThemeStr] = []
        tmp = ""
        for ch in item:
            if ch in separator_lookup:
                if tmp:
                    if subnet:
                        _vlist.append(ThemeStr(tmp, ThemeAttr("types", "ipmask"), selected))
                    else:
                        _vlist.append(ThemeStr(tmp, ThemeAttr("types", "address"), selected))
                _vlist.append(separator_lookup[ch])
                tmp = ""

                if ch == "/":
                    subnet = True
            else:
                tmp += ch

        if tmp:
            if subnet:
                _vlist.append(ThemeStr(tmp, ThemeAttr("types", "ipmask"), selected))
            else:
                _vlist.append(ThemeStr(tmp, ThemeAttr("types", "address"), selected))
        if array:
            item_separator.selected = selected
            array.append(item_separator)
        array += _vlist

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"), selected)
        ]

    return array
