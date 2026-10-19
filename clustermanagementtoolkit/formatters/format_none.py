# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable=unused-argument
def format_none(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    Noop formatter; returns the text without syntax highlighting.

        Parameters:
            lines ([str]): A list of strings
            *or*
            lines (str): a string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([themearray]): A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    for line in lines:
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
    return dumps
