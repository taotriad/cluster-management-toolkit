# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for timestamps.
"""

from datetime import datetime

from clustermanagementtoolkit.cmtlib import datetime_to_timestamp

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.format_special import format_special


def format_timestamp(timestamp: str | datetime, selected: bool) -> list[ThemeRef | ThemeStr]:
    """
    Format a timestamp.

        Parameters:
            timestamp (str | timestamp): The timestamp to format
            selected (bool): Is the string selected?
        Returns:
            ([ThemeRef | ThemeStr]): A ThemeArray
    """
    array: list[ThemeRef | ThemeStr] = []
    string: str = ""

    if isinstance(timestamp, str):
        if (tmp := format_special(timestamp, selected)) is not None:
            array = [tmp]
        string = timestamp

    if not array:
        if not isinstance(timestamp, str):
            string = datetime_to_timestamp(timestamp)
        if timestamp is None or timestamp == datetime.fromtimestamp(0).astimezone():
            array = [
                ThemeStr(string, ThemeAttr("types", "generic"), selected)
            ]
        else:
            array = format_numerical_with_units(string, selected, ftype="numerical")

    return array
