# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def sysctl(message: str, **kwargs: Any) -> tuple[str, LogLevel, str | list[ThemeRef | ThemeStr],
                                                 list[tuple[list[ThemeRef | ThemeStr],
                                                            LogLevel]]]:
    """
    Format output from sysctl.

        Parameters:
            message (str): The string to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
        Returns:
            (str|ThemeArray, LogLevel, str, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The untouched or formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")

    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []
    new_message: list[ThemeRef | ThemeStr] = []

    kv = message.split(" = ")
    if len(kv) != 2:
        return facility, severity, message, remnants
    key, value = kv
    keyparts = key.split(".")
    for i, part in enumerate(keyparts):
        new_message.append(ThemeStr(part, ThemeAttr("types", "key")))
        if i < len(keyparts) - 1:
            new_message.append(ThemeRef("separators", "sysctl_key_components"))
    new_message.append(ThemeRef("separators", "sysctl_keyvalue"))
    new_message.append(ThemeStr(value, ThemeAttr("types", "value")))
    return facility, severity, new_message, remnants
