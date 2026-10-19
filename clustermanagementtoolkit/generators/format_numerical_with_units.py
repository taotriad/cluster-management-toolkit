# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for numerical strings, optionally containing units.
"""

from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=too-many-branches,too-many-statements
def format_numerical_with_units(string: str,
                                selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a string, return it formatted with the numerical parts
    highlighted with the formatting for numerical values, and the remaining
    characters formatted as units.
    Note that decimal points will also be formatted as units.

        Parameters:
            string (str): The string to format
            selected (bool): Should the string be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                ftype (str): The formatting type for the non-units
                non_units (set[str]): The characters to treat as non-units (default: 0-9)
                separator_lookup (dict): The formatting to use for units
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    ftype = deep_get(kwargs, DictPath("ftype"), "numerical")
    non_units: set | None = deep_get(kwargs, DictPath("non_units"), None)
    separator_lookup: dict | None = deep_get(kwargs, DictPath("separator_lookup"), None)
    substring: str = ""
    array: list[ThemeRef | ThemeStr] = []
    numeric = None
    # This is necessary to be able to use pop
    liststring = list(string)

    if separator_lookup is None:
        separator_lookup = {}

    if "default" not in separator_lookup:
        separator_lookup["default"] = ThemeAttr("types", "unit")

    if non_units is None:
        non_units = set("0123456789₀₁₂₃₄₅₆₇₈₉⁰¹²³⁴⁵⁶⁷⁸⁹")
    else:
        non_units = set(non_units)

    while liststring:
        char = liststring.pop(0)
        if numeric is None:
            numeric = char in non_units
            substring += char
        elif numeric:
            # Do we need to flush?
            if char not in non_units:
                if selected is None:
                    array.append(ThemeStr(substring, ThemeAttr("types", ftype)))
                else:
                    array.append(ThemeStr(substring, ThemeAttr("types", ftype), selected))
                substring = ""
                numeric = False

            substring += char
        else:
            # Do we need to flush?
            if char in non_units:
                fmt = cast(ThemeAttr,
                           deep_get_with_fallback(separator_lookup,
                                                  [DictPath(substring), DictPath("default")]))
                if selected is None:
                    array.append(ThemeStr(substring, fmt))
                else:
                    array.append(ThemeStr(substring, fmt, selected))
                substring = ""
                numeric = True
            substring += char

        if not liststring:
            if numeric:
                if selected is None:
                    array.append(ThemeStr(substring, ThemeAttr("types", ftype)))
                else:
                    array.append(ThemeStr(substring, ThemeAttr("types", ftype), selected))
            else:
                fmt = cast(ThemeAttr, deep_get_with_fallback(separator_lookup,
                                                             [DictPath(substring),
                                                              DictPath("default")]))
                if selected is None:
                    array.append(ThemeStr(substring, fmt))
                else:
                    array.append(ThemeStr(substring, fmt, selected))

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"), selected)
        ]

    return array
