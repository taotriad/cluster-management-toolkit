# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Convert a LogLevel to a 1-letter string representation.
"""

from clustermanagementtoolkit.cmttypes import LogLevel


def lvl_to_letter_severity(lvl: LogLevel) -> str:
    """
    Convert a LogLevel to a 1-letter severity string.

        Parameters:
            lvl (LogLevel): A LogLevel
        Returns:
            (str): The corresponding severity string
    """
    severities: dict[LogLevel, str] = {
        LogLevel.CRIT: "C",
        LogLevel.ERR: "E",
        LogLevel.WARNING: "W",
        LogLevel.NOTICE: "N",
        LogLevel.INFO: "I",
        LogLevel.DEBUG: "D",
    }
    return severities.get(lvl, "!ERROR IN LOGPARSER!")
