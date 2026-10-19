# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def reformat_message_remnants(message: str | list[ThemeRef | ThemeStr],
                              remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]],
                              severity: LogLevel) \
        -> tuple[list[ThemeRef | ThemeStr], list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Given message and remnants, either format the message and return the remnants
    untouched or, if the message is empty, return the first remnants as message,
    and the rest as the new remnants. If message is already in ThemeArray format,
    the message will be left untouched.

        Parameters:
            message (str): The message to format
            remnants ([(ThemeArray, LogLevel)]): The remnants to extract a new message from
            severity (LogLevel): The severity to use for the formatted message
        Returns:
            (ThemeArray, [(ThemeArray, LogLevel)]):
    """
    # If message is a list we assume it's a ThemeArray.
    if not isinstance(message, str):
        return message, remnants

    # message is a string, and it already has data.
    if message:
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        return [ThemeStr(message, ThemeAttr("logview", severity_name))], remnants

    # message is a string (or might be empty), but has no data;
    # give it the first row from remnants.
    try:
        message, _severity = remnants.pop(0)
    except IndexError:
        message = []
    return message, remnants
