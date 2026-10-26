# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for URIs.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.format_list import format_list
from clustermanagementtoolkit.generators.format_uri import format_uri


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_uri(obj: dict, field: str, fieldlen: int, pad: bool,
                  ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    A generator for URIs.

        Parameters:
            obj (dict): The object to get data from
            field (str): The field in the object to get data from
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Should the text be right-aligned?
            selected (bool): Should the generated field be selected?
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    items = deep_get(obj, DictPath(field), [])

    if isinstance(items, str) and items in ("<unset>", "<none>"):
        return format_list([items], fieldlen, pad, ralign=ralign, selected=selected)

    item_separator = deep_get(kwargs, DictPath("item_separator"),
                              ThemeRef("separators", "list", selected))

    array = format_uri(items, selected, item_separator=item_separator)

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
