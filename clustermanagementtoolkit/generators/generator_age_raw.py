# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for age that bypasses lookups.
"""

from clustermanagementtoolkit.cmtlib import seconds_to_age

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.format_special import format_special


def generator_age_raw(value: int | str, selected: bool) -> list[ThemeRef | ThemeStr]:
    """
    A generator for age that operates directly on a value instead of doing a lookup first.

        Parameters:
            value (Any): The value to convert to age
            selected (bool): Is the string selected?
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []

    if value == -1:
        string = ""
    elif isinstance(value, str):
        string = value
    else:
        string = seconds_to_age(value, negative_is_skew=True)

    if (tmp := format_special(string, selected)) is not None:
        array = [tmp]
    elif string == "<clock skew detected>":
        fmt = ThemeAttr("main", "status_not_ok")
        array = [
            ThemeStr(string, fmt, selected)
        ]
    else:
        array = format_numerical_with_units(string, selected, ftype="age")

    return array
