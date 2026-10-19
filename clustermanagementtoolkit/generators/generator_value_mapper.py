# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for value mapping.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.map_value import map_value


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_value_mapper(obj: dict, field: "str", fieldlen: int, pad: bool,
                           ralign: bool, selected: bool,
                           **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate a formatted string with value mapping.

        Parameters:
            obj (dict): The object to get data from
            field (str): The field in the object to get data from
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Should the text be right-aligned?
            selected (bool): Should the generated field be selected?
            **kwargs (dict[str, Any]): Keyword arguments
                field_colors ([ThemeAttr]): The colors to use for each member in a field
                mapping (dict): Mappings passed to map_value()
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []
    value = deep_get(obj, DictPath(field))

    default_field_color = deep_get(kwargs, DictPath("field_colors"), [("types", "generic")])[0]

    formatted_string, _string = map_value(value,
                                          selected=selected,
                                          default_field_color=default_field_color,
                                          mapping=deep_get(kwargs, DictPath("mapping"), {}))
    array = [
        formatted_string
    ]

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
