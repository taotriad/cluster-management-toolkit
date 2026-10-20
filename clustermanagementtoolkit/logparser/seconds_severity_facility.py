# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert messages in [seconds] SEVERITY facility message format.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity


# input: [     0.000384s]  INFO ThreadId(01) linkerd2_proxy::rt: Using single-threaded proxy runtime
# output:
#   severity: LogLevel.INFO
#   facility: ThreadId(01)
#   msg: [     0.000384s] linkerd2_proxy::rt: Using single-threaded proxy runtime
#   remnants: []
# pylint: disable-next=unused-argument
def seconds_severity_facility(message: str, **kwargs: Any) \
        -> tuple[str, LogLevel, str | list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Convert messages in [seconds] SEVERITY facility message format.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ((str, LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]))):
                (str): The log facility
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The unchanged message if nothing matched,
                                  or the formatted themearray
                ([(ThemeArray, LogLevel)]): [unused]
    """
    facility: str = ""
    severity: LogLevel = LogLevel.INFO
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    re_tmp = re.match(r"(\[\s*?\d+?\.\d+?s\])\s+([A-Z]+?)\s+(\S+?)\s(.*)", message)
    if re_tmp is not None:
        severity = str_to_severity(re_tmp[2], default=severity)
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        facility = re_tmp[3]
        new_message: list[ThemeRef | ThemeStr] = \
            [ThemeStr(f"{re_tmp[1]} ", ThemeAttr("logview", "timestamp")),
             ThemeStr(f"{re_tmp[4]}", ThemeAttr("logview", severity_name))]
        return facility, severity, new_message, remnants

    return facility, severity, message, remnants
