# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format an address suffixed with a port number; kept separate from format_address()
to avoid issues with IPv6-addresses.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def format_address_with_port(items: str | list[str],
                             selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a list of strings, return them formatted as addresses with ports;
    this has to be kept separate from address since IPv6-address can be of the form
    <...>:<digit> which would be mistaken for <address>:<port>.

        Parameters:
            items (str|[str]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                item_separator (ThemeRef): Separator between items
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    if isinstance(items, (str, tuple)):
        items = [items]

    item_separator = deep_get(kwargs, DictPath("item_separator"),
                              ThemeRef("separators", "list", selected))

    separator_lookup = {}

    separators = [ThemeRef("separators", "ipv4address", selected),
                  ThemeRef("separators", "ipv6address", selected)]

    for separator in separators:
        separator_lookup[str(separator)] = separator

    array: list[ThemeRef | ThemeStr] = []

    for item in items:
        try:
            address, port = item.rsplit(":", maxsplit=1)
        except ValueError:
            address = item
            port = ""

        _vlist: list[ThemeRef | ThemeStr] = []
        tmp = ""
        for ch in address:
            if ch in separator_lookup:
                if tmp:
                    _vlist.append(ThemeStr(tmp, ThemeAttr("types", "address"), selected))
                _vlist.append(separator_lookup[ch])
                tmp = ""
            else:
                tmp += ch

        if tmp:
            _vlist.append(ThemeStr(tmp, ThemeAttr("types", "address"), selected))
        if port:
            _vlist.append(ThemeRef("separators", "port", selected))
            _vlist.append(ThemeStr(port, ThemeAttr("types", "port"), selected))
        if array:
            item_separator.selected = selected
            array.append(item_separator)
        array += _vlist

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"), selected)
        ]

    return array
