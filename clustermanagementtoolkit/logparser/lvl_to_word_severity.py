# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmttypes import LogLevel


def lvl_to_word_severity(lvl: LogLevel) -> str:
    """
    Convert a LogLevel to a severity string.

        Parameters:
            lvl (LogLevel): A LogLevel
        Returns:
            (str): The corresponding severity string
    """
    severities: dict[LogLevel, str] = {
        LogLevel.CRIT: "CRITICAL",
        LogLevel.ERR: "ERROR",
        LogLevel.WARNING: "WARNING",
        LogLevel.NOTICE: "NOTICE",
        LogLevel.INFO: "INFO",
        LogLevel.DEBUG: "DEBUG",
    }
    return severities.get(lvl, "!ERROR IN LOGPARSER!")
