# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert 3-letter severity to LogLevel.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


# Used by Kiali and kubeshark.
def str_3letter_to_severity(string: str, **kwargs: Any) -> LogLevel:
    """
    Convert a 3-letter severity string to a LogLevel.

        Parameters:
            letter (str): A 3-letter severity string
            **kwargs (dict[str, Any]): Keyword arguments
                default (LogLevel): The loglevel to return if the input is invalid
        Returns:
            (LogLevel): The corresponding LogLevel
    """
    default: LogLevel = deep_get(kwargs, DictPath("default"), LogLevel.DEFAULT)
    severities = {
        "ERR": LogLevel.ERR,
        "WRN": LogLevel.WARNING,
        "INF": LogLevel.INFO,
        "DBG": LogLevel.DEBUG,
        "TRC": LogLevel.DEBUG,  # Most likely TRACE; no reason for different loglevel
    }
    return deep_get(severities, DictPath(string.upper()), default)
