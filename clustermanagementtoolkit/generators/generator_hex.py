# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for addresses.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.format_special import format_special


# pylint: disable-next=unused-argument,too-many-arguments,too-many-positional-arguments
def generator_hex(obj: dict, field: str, fieldlen: int, pad: bool,
                  ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    A generator for hexadecimal values.

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
    array: list[ThemeRef | ThemeStr] = []
    value = deep_get(obj, DictPath(field))
    string = str(value)
    tmp: Any = None

    if (tmp := format_special(string, selected)) is not None:
        array = [tmp]
    else:
        if string.startswith(("sha224", "sha256", "sha384", "sha512")):
            tmp = string.split(":", maxsplit=1)
            array += [ThemeStr(tmp[0], ThemeAttr("main", "highlight"), selected)]
            string = f":{tmp[1]}"
        array += format_numerical_with_units(string, selected, ftype="numerical",
                                             non_units=set("0123456789abcdefABCDEF"))

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
