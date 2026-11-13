# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for value mapping.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.map_value import map_value


def format_map_value(items: str | list[str],
                     selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a string, format using the value mapper.

        Parameters:
            items (str|[str]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []
    mapping: dict[str, Any] = deep_get(kwargs, DictPath("formatting#mapping"), {})
    default_field_color: ThemeAttr = deep_get(kwargs, DictPath("default_field_color"))

    formatted_string, _string = map_value(items, selected=selected,
                                          default_field_color=default_field_color,
                                          mapping=mapping)
    array = [
        formatted_string
    ]

    return array
