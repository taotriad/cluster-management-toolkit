# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for lists.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.format_list import format_list


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_list(obj: dict, field: str, fieldlen: int, pad: bool,
                   ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate a formatted list, with support for custom list separators,
    grouped tuples, ellipsising after a certain length, etc.

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
    items = deep_get(obj, DictPath(field))

    return format_list(items, fieldlen, pad, ralign=ralign, selected=selected, **kwargs)
