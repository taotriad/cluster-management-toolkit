# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for basic strings.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_basic(obj: dict, field: str, fieldlen: int, pad: bool,
                    ralign: bool, selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    The default generator; it knows about certain special strings,
    but otherwise will use the provided formatting.

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
    value = deep_get(obj, DictPath(field))
    string = str(value)
    field_colors = deep_get(kwargs, DictPath("field_colors"), [ThemeAttr("types", "generic")])

    if string == "None":
        string = "<none>"

    if string in ("<none>", "<unknown>"):
        fmt = ThemeAttr("types", "none")
    elif string in ("<default>", "<unbounded>"):
        fmt = ThemeAttr("types", "default")
    elif string in ("<undefined>", "<unspecified>"):
        fmt = ThemeAttr("types", "undefined")
    elif string in ("<empty>", "<unset>"):
        fmt = ThemeAttr("types", "unset")
    else:
        context, attr_ref = field_colors[0]
        fmt = ThemeAttr(context, attr_ref)

    array = [
        ThemeStr(string, fmt, selected)
    ]

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
