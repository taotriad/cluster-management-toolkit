# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for memory consumption.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.generator_basic import generator_basic


def __remove_units(numstr: str) -> str:
    if not (unitfree := re.match(r"^(\d+).*", numstr)):
        raise ValueError(f"Could not remove unit from string {numstr}")
    return unitfree[1]


# pylint: disable-next=unused-argument,too-many-arguments,too-many-positional-arguments
def generator_mem(obj: dict, field: str, fieldlen: int, pad: bool,
                  ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate formatting for memory usage tuples (free / total).

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
    array: list[ThemeRef | ThemeStr] = []
    tmp_free, tmp_total = deep_get(obj, DictPath(field))
    free = __remove_units(tmp_free)
    total = __remove_units(tmp_total)

    if free is None and total is None:
        return generator_basic(obj, field, fieldlen, pad, ralign, selected)

    used = f"{100 - (100 * int(free) / int(total)):0.1f}"

    if float(used) < 80.0:
        fmt = ThemeAttr("types", "watermark_low")
    elif float(used) < 90.0:
        fmt = ThemeAttr("types", "watermark_medium")
    else:
        fmt = ThemeAttr("types", "watermark_high")

    total = f"{int(total) / (1024 * 1024):0.1f}"
    unit = "GiB"

    array = [
        ThemeStr(used, fmt, selected),
        ThemeRef("separators", "percentage", selected),
        ThemeStr(" ", fmt, selected),
        ThemeRef("separators", "fraction", selected),
        ThemeStr(" ", fmt, selected),
        ThemeStr(total, ThemeAttr("types", "numerical"), selected),
        ThemeStr(unit, ThemeAttr("types", "unit"), selected),
    ]

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
