# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for timestamps that also includes age.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import datetime_to_timestamp
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.generator_age_raw import generator_age_raw


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_timestamp_with_age(obj: dict, field: str, fieldlen: int, pad: bool,
                                 ralign: bool, selected: bool,
                                 **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate a formatted string either from a timestamp or a string;
    with both timestamp *and* age. Typically used to represent timestamp + duration.

        Parameters:
            obj (dict): The object to get data from
            field (str): The field in the object to get data from
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Should the text be right-aligned?
            selected (bool): Should the generated field be selected?
            **kwargs (dict[str, Any]): Keyword arguments
                field_colors ([ThemeAttr]): The colors to use for each member in a field
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []
    values = deep_get(obj, DictPath(field))

    field_colors = deep_get(kwargs, DictPath("field_colors"), [])

    if len(field_colors) < 2 < len(values):
        raise ValueError("Received more than 2 fields for timestamp_with_age "
                         "but no formatting to specify what the values signify")

    if len(values) == 2:
        if values[0] is None:
            array = [
                ThemeStr("<none>", ThemeAttr("types", "none"), selected)
            ]
        else:
            timestamp_string = datetime_to_timestamp(values[0])
            array = format_numerical_with_units(timestamp_string, selected, ftype="timestamp")
            array += [
                ThemeStr(" (", ThemeAttr("types", "generic"), selected)
            ]
            array += generator_age_raw(values[1], selected)
            array += [
                ThemeStr(")", ThemeAttr("types", "generic"), selected)
            ]
    else:
        array = []

        for i, data in enumerate(values):
            # If there's no formatting for this field we assume that
            # it is a generic string
            if len(field_colors) <= i:
                fmt = ThemeAttr("types", "generic")
                array += [ThemeStr(data, fmt, selected)]
            elif field_colors[i] == ThemeAttr("types", "timestamp"):
                if data is None:
                    array += [
                        ThemeStr("<unset>", ThemeAttr("types", "none"), selected)
                    ]
                    break

                timestamp = timestamp_to_datetime(data)
                timestamp_string = f"{timestamp.astimezone():%Y-%m-%d %H:%M:%S}"
                array += format_numerical_with_units(timestamp_string, selected, ftype="timestamp")
            elif field_colors[i] == ThemeAttr("types", "age"):
                array += generator_age_raw(data, selected)
            else:
                array += [
                    ThemeStr(data, field_colors[i], selected)
                ]

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
