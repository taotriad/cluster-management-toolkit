# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format a URI.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.format_address import format_address


# pylint: disable-next=too-many-branches
def format_uri(items: str | list[str],
               selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a list of strings, return them formatted as URIs.

        Parameters:
            items (str|[str]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                formatting (FormattingType): Formatting for the data
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    if isinstance(items, (str, tuple)):
        items = [items]

    item_separator = deep_get(kwargs, DictPath("item_separator"),
                              ThemeRef("separators", "list", selected))

    array: list[ThemeRef | ThemeStr] = []

    for item in items:
        # If the object is a tuple we assume it's an URI made up of parts that should be joined.
        if isinstance(item, tuple):
            item = "".join(item)
        _vlist: list[ThemeRef | ThemeStr] = []
        urisplit = item.split("://", maxsplit=1)
        if len(urisplit) != 2:
            # This isn't a properly formatted URI, just add it unformatted.
            _vlist = [ThemeStr(item, ThemeAttr("types", "generic"), selected)]
        else:
            scheme = urisplit[0]
            rest = urisplit[1]

            # Split the server address from the rest.
            urisplit = rest.split("/", maxsplit=1)
            authority = urisplit[0]
            uripath: list[ThemeRef | ThemeStr] = []
            if len(urisplit) == 2:
                # We have a path too; split and rejoin it with formatting.
                uripathsplit = urisplit[1].split("/")
                uripath = []
                for segment in uripathsplit:
                    if uripath:
                        uripath += [ThemeRef("separators", "uri_path", selected)]
                    uripath += [ThemeStr(segment, ThemeAttr("types", "address"), selected)]
            urisplit = authority.split(":")
            if len(urisplit) > 2:
                # This URI is malformed.
                _vlist = [ThemeStr(item, ThemeAttr("types", "generic"), selected)]
            else:
                _vlist = [ThemeStr(scheme, ThemeAttr("types", "protocol"), selected)]
                _vlist += [ThemeRef("separators", "uri_separator", selected)]
                _vlist += format_address(authority, selected, item_separator=item_separator)
                if uripath:
                    _vlist += [ThemeRef("separators", "uri_path", selected)]
                    _vlist += uripath

        if array:
            item_separator.selected = selected
            array.append(item_separator)
        array += _vlist

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"), selected)
        ]

    return array
