# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the ThemeAttr matching a severity.
"""

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes.loglevel_to_name import loglevel_to_name

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr


def color_log_severity(severity: LogLevel) -> ThemeAttr:
    """
    Given severity, returns the corresponding ThemeAttr.

        Parameters:
            severity (LogLevel): The severity
        Returns:
            (ThemeAttr): The corresponding ThemeAttr
    """
    return ThemeAttr("logview", f"severity_{loglevel_to_name(severity).lower()}")
