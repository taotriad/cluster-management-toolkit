# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def merge_message(message: str | list[ThemeRef | ThemeStr], **kwargs: Any) \
        -> tuple[str, list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Given message + remnants, merge the message into the remnants and return an empty message.

        Parameters:
            message (str|themearray): The string to merge into remnants
            **kwargs (dict[str, Any]): Keyword arguments
                remnants (list[(themearray, LogLevel)]): The list of remnants
                severity (LogLevel): The severity for message
        Returns:
            (message, remnants):
                message (str): The newly emptied message
                remnants (list[(themearray, LogLevel)]): Remnants with message preprended
    """
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = \
        deep_get(kwargs, DictPath("remnants"))
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)

    # This is a ThemeArray
    if isinstance(message, list):
        if remnants is not None:
            remnants = [(message, severity)] + remnants
        else:
            remnants = message
    else:
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        if remnants is not None:
            remnants.insert(0,
                            ([ThemeStr(message, ThemeAttr("logview", severity_name))], severity))
        else:
            remnants = [([ThemeStr(message, ThemeAttr("logview", severity_name))], severity)]
    message = ""

    return message, remnants
