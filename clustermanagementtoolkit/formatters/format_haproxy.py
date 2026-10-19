# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmtlib import split_msg

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.formatters.format_none import format_none


def format_haproxy(lines: str | list[str], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    HAProxy formatter; returns the text with syntax highlighting for HAProxy.

        Parameters:
            lines (list[str]): A list of strings
            *or*
            lines (str): A string with newlines that should be split
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            list[themearray]: A list of themearrays
    """
    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, str):
        lines = split_msg(lines)

    if deep_get(kwargs, DictPath("raw"), False):
        return format_none(lines)

    haproxy_section_regex: re.Pattern[str] = re.compile(r"^(\s*)(global|defaults|frontend|"
                                                        "backend|listen|resolvers|"
                                                        r"mailers|peers)(\s*)(.*)")
    haproxy_setting_regex: re.Pattern[str] = re.compile(r"^(\s*)(\S+)(\s+)(.+)")

    for line in lines:
        # Is it whitespace?
        if not line.strip():
            dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])
            continue

        # Is it a new section?
        tmp = haproxy_section_regex.match(line)
        if tmp is not None:
            whitespace1 = tmp[1]
            section = tmp[2]
            whitespace2 = tmp[3]
            label = tmp[4]
            tmpline: list[ThemeRef | ThemeStr] = [
                ThemeStr(whitespace1, ThemeAttr("types", "generic")),
                ThemeStr(section, ThemeAttr("types", "haproxy_section")),
                ThemeStr(whitespace2, ThemeAttr("types", "generic")),
                ThemeStr(label, ThemeAttr("types", "haproxy_label")),
            ]
            dumps.append(tmpline)
            continue

        # Is it settings?
        tmp = haproxy_setting_regex.match(line)
        if tmp is not None:
            whitespace1 = tmp[1]
            setting = tmp[2]
            whitespace2 = tmp[3]
            values = tmp[4]
            tmpline = [
                ThemeStr(whitespace1, ThemeAttr("types", "generic")),
                ThemeStr(setting, ThemeAttr("types", "haproxy_setting")),
                ThemeStr(whitespace2, ThemeAttr("types", "generic")),
                ThemeStr(values, ThemeAttr("types", "generic")),
            ]
            dumps.append(tmpline)
            continue

        # Unknown data; just append it unformatted
        dumps.append([ThemeStr(line, ThemeAttr("types", "generic"))])

    return dumps
