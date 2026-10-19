# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.letter_to_severity import letter_to_severity


def split_glog(message: str, **kwargs: Any) \
        -> tuple[str, LogLevel, str, list[tuple[list[ThemeRef | ThemeStr], LogLevel]], bool]:
    """
    Extract messages in glog format.

        Parameters:
            message (str): The message to reformat
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The current loglevel
                facility (str): The current facility
        Returns:
            (facility, severity, facility, message, remnants, matched)
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.DEFAULT)
    facility: str = deep_get(kwargs, DictPath("facility"), "")

    matched: bool = False
    loggingerror = None
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    # Workaround a bug in use of glog; to make the logged message useful
    # we separate it from the warning about glog use; this way we can get the proper severity
    if message.startswith("ERROR: logging before flag.Parse: "):
        loggingerror = "ERROR: logging before flag.Parse"
        message = message.removeprefix("ERROR: logging before flag.Parse: ")

    re_tmp = \
        re.match(r"^([A-Z]\d{4} \d\d:\d\d:\d\d\.\d)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z (.*)",
                 message)
    if re_tmp is not None:
        message = f"{re_tmp[1]}{re_tmp[2]}"

    re_tmp = re.match(r"^([A-Z])\d\d\d\d \d\d:\d\d:\d\d\.\d+\s+(\d+)\s(.+?:\d+)\](.*)", message)
    re_tmp2 = re.match(r"^(\[[A-Z])\d{3,4} \d\d:\d\d:\d\d\.\d+\s+(.+?:\d+)\](.*)", message)

    if re_tmp is not None:
        severity = letter_to_severity(re_tmp[1])

        # We do not use PID, but it is here just to document the meaning of the field
        # _pid = re_tmp[2]

        facility = f"{(re_tmp[3])}"
        message = f"{(re_tmp[4])}"
        # The first character is always whitespace unless this is an empty line.
        if message:
            message = message[1:]
        matched = True
    elif re_tmp2 is not None:
        severity = letter_to_severity(re_tmp2[1])

        facility = f"{(re_tmp2[2])}"
        message = f"{(re_tmp2[3])}"
        # The first character is always whitespace unless this is an empty line.
        if message:
            message = message[1:]
        matched = True
    else:
        if severity is None:
            severity = LogLevel.INFO

    # If we have a logging error we return that as message and the rest as remnants.
    if loggingerror is not None:
        severity = LogLevel.ERR
        remnants.insert(0,
                        ([ThemeStr(message,
                                   ThemeAttr("logview",
                                             f"severity_{loglevel_to_name(severity).lower()}"))],
                         severity))
        message = loggingerror

    return facility, severity, message, remnants, matched
