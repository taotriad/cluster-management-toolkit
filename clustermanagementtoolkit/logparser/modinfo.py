# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format the output from modinfo.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import LogLevel

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=unused-argument
def modinfo(message: str, **kwargs: Any) \
        -> tuple[str, LogLevel, str | list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Format the output from the Linux modinfo command.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ((str, LogLevel, str, [(ThemeArray, LogLevel)]))):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The unchanged message if nothing matched,
                                  or the formatted themearray
                ([(ThemeArray, LogLevel)]): [unused]
    """
    facility = ""
    severity = LogLevel.INFO
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    if (re_tmp := re.match(r"^([a-z][\S]*?):(\s+)(.+)", message)) is not None:
        key = re_tmp[1]
        whitespace = re_tmp[2]
        value = re_tmp[3]
        new_message: list[ThemeRef | ThemeStr] = [
            ThemeStr(key, ThemeAttr("types", "key")),
            ThemeRef("separators", "keyvalue"),
            ThemeStr(whitespace, ThemeAttr("types", "generic")),
            ThemeStr(value, ThemeAttr("types", "value")),
        ]
        return facility, severity, new_message, remnants
    return facility, severity, message, remnants
