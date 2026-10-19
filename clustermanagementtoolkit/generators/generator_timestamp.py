# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for timestamps.
"""

from datetime import datetime
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.format_timestamp import format_timestamp


# pylint: disable-next=unused-argument,too-many-arguments,too-many-positional-arguments
def generator_timestamp(obj: dict, field: str, fieldlen: int, pad: bool,
                        ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate a formatted string either from a timestamp or a string;
    special strings such as "<none>" are also handled.

        Parameters:
            obj (dict): The object to get data from
            field (str): The field in the object to get data from
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Should the text be right-aligned?
            selected (bool): Should the generated field be selected?
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    value: str | datetime = deep_get(obj, DictPath(field))

    array = format_timestamp(value, selected=selected)

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
