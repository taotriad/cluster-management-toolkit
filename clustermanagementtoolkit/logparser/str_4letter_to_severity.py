# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def str_4letter_to_severity(string: str, **kwargs: Any) -> LogLevel:
    """
    Convert a 4-letter severity string to a LogLevel.

        Parameters:
            letter (str): A 4-letter severity string
            **kwargs (dict[str, Any]): Keyword arguments
                default (LogLevel): The loglevel to return if the input is invalid
        Returns:
            (LogLevel): The corresponding LogLevel
    """
    default: LogLevel = deep_get(kwargs, DictPath("default"), LogLevel.DEFAULT)
    severities = {
        "CRIT": LogLevel.CRIT,
        "FATA": LogLevel.CRIT,
        "ERRO": LogLevel.ERR,
        "WARN": LogLevel.WARNING,
        "NOTI": LogLevel.NOTICE,
        "SUCC": LogLevel.NOTICE,  # From KubeRay
        "INFO": LogLevel.INFO,
        "DEBU": LogLevel.DEBUG,
        "DEBG": LogLevel.DEBUG,
    }
    return deep_get(severities, DictPath(string.upper()), default)
