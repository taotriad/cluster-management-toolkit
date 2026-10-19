# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmttypes import LogLevel


def lvl_to_4letter_severity(lvl: LogLevel) -> str:
    """
    Convert a LogLevel to a 4-letter severity string.

        Parameters:
            lvl (LogLevel): A LogLevel
        Returns:
            (str): The corresponding severity string
    """
    severities: dict[LogLevel, str] = {
        LogLevel.CRIT: "CRIT",
        LogLevel.ERR: "ERRO",
        LogLevel.WARNING: "WARN",
        LogLevel.NOTICE: "NOTI",
        LogLevel.INFO: "INFO",
        LogLevel.DEBUG: "DEBU",
    }
    return severities.get(lvl, "!ERROR IN LOGPARSER!")
