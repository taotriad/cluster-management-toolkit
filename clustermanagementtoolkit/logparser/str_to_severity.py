# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def str_to_severity(string: str, **kwargs: Any) -> LogLevel:
    """
    Convert a severity string to a LogLevel.

        Parameters:
            letter (str): A severity string
            **kwargs (dict[str, Any]): Keyword arguments
                default (LogLevel): The loglevel to return if the input is invalid
        Returns:
            (LogLevel): The corresponding LogLevel
    """
    default: LogLevel = deep_get(kwargs, DictPath("default"), LogLevel.DEFAULT)
    severities = {
        "critical": LogLevel.CRIT,
        "fatal": LogLevel.CRIT,
        "error": LogLevel.ERR,
        "eror": LogLevel.ERR,
        "warning": LogLevel.WARNING,
        "warn": LogLevel.WARNING,
        "notice": LogLevel.NOTICE,
        "noti": LogLevel.NOTICE,
        "info": LogLevel.INFO,
        "debug": LogLevel.DEBUG,
        "debu": LogLevel.DEBUG,
        "dbg": LogLevel.DEBUG,
    }
    # Special case for severity found in trust-manager
    if string.lower().startswith("debug+") \
            and re.match(r"debug\+(\d+)$", string, re.IGNORECASE) is not None:
        return LogLevel.DEBUG
    # Special case for severity found in jobset
    level_regex = re.compile(r"LEVEL\((-\d+)\)")
    if (re_tmp := level_regex.match(string)) is not None:
        severity = int(re_tmp[1])
        # We can only guess for now; the negative loglevels
        # might be custom for JobSet and LeaderWorkerSet;
        # but at least -2 seems to be Info.
        if severity == -2:
            return LogLevel.INFO
    return deep_get(severities, DictPath(string.lower()), default)
