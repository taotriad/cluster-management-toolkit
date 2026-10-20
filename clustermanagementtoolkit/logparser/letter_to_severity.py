# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert 1-letter severity to LogLevel.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


# Mainly used by glog
def letter_to_severity(letter: str, **kwargs: Any) -> LogLevel:
    """
    Convert a 1-letter severity string to a LogLevel.

        Parameters:
            letter (str): A 1-letter severity string
            **kwargs (dict[str, Any]): Keyword arguments
                default (LogLevel): The loglevel to return if the input is invalid
        Returns:
            (LogLevel): The corresponding LogLevel
    """
    default: LogLevel = deep_get(kwargs, DictPath("default"), LogLevel.DEFAULT)
    severities = {
        "F": LogLevel.EMERG,
        "E": LogLevel.ERR,
        "W": LogLevel.WARNING,
        "N": LogLevel.NOTICE,
        "C": LogLevel.NOTICE,  # Used by jupyter for the login token
        "I": LogLevel.INFO,
        "D": LogLevel.DEBUG,
    }
    return deep_get(severities, DictPath(letter), default)
