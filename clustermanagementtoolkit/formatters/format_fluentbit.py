# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for FluentBit.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.format_none import format_none


def format_fluentbit(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    FluentBit formatter; returns the text with syntax highlighting for FluentBit.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    if isinstance(lines, str):
        lines = split_msg(lines)

    key_value_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S*)(\s*)(.*)")

    for line in lines:
        tmpline: list[ThemeRef | ThemeStr] = []

        if line.lstrip().startswith("#"):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_comment")),
            ]
        elif line.lstrip().startswith("[") and line.rstrip().endswith("]"):
            tmpline = [
                ThemeStr(line, ThemeAttr("types", "ini_section")),
            ]
        elif not line.strip():
            tmpline = [
                ThemeStr("", ThemeAttr("types", "generic")),
            ]
        else:
            tmp = key_value_regex.match(line)
            if tmp is not None:
                indentation = tmp[1]
                key = tmp[2]
                separator = tmp[3]
                value = tmp[4]

                tmpline = [
                    ThemeStr(f"{indentation}", ThemeAttr("types", "generic")),
                    ThemeStr(f"{key}", ThemeAttr("types", "ini_key")),
                    ThemeStr(f"{separator}", ThemeAttr("types", "ini_separator")),
                    ThemeStr(f"{value}", ThemeAttr("types", "ini_value")),
                ]
        if tmpline:
            dumps.append(tmpline)
    return dumps
