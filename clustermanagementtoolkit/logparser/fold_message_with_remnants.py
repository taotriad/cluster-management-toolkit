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
from clustermanagementtoolkit.curses_helper import themearray_flatten
from clustermanagementtoolkit.curses_helper import themearray_rstrip


# pylint: disable-next=too-many-branches
def fold_message_with_remnants(message: str | list[ThemeRef | ThemeStr],
                               remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]],
                               severity: LogLevel, pad: str = "none") -> list[ThemeRef | ThemeStr]:
    """
    Given message and remnants, fold the remnants into the message;
    this is only intended to be used with structured formats, such as key=value.

        Parameters:
            message (str|ThemeArray): The message to format
            remnants ([(ThemeArray, LogLevel)]): The remnants to merge into the message
            severity (LogLevel): The severity to use for the formatted message
            pad (str): Add padding.
                       "none": No padding [default]
                       "message": Padding after message
                       "all": Add padding between all remnants; if all is used
                              the message will not be reformatted afterwards
        Returns:
            (ThemeArray): The folded message
    """
    if not message and not remnants:
        return []

    # If message is a string we need to reformat it as a ThemeArray.
    if isinstance(message, str):
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        message = [ThemeStr(message, ThemeAttr("logview", severity_name))]

    if not remnants:
        return message

    new_message = message

    if pad == "message":
        new_message.append(ThemeStr(" ", ThemeAttr("types", "generic"), selected=False))

    for line, _severity in remnants:
        if pad == "all":
            new_message.append(ThemeStr(" ", ThemeAttr("types", "generic"), selected=False))
        new_message += themearray_rstrip(themearray_flatten(line))

    # OK, we've joined everything into one line; now time for reformatting it.
    message = []
    prevstr: str = ""
    prevfmt: ThemeAttr | None = None

    # Reformatting won't work unless we substitute ThemeRefs.
    for segment in themearray_flatten(new_message):
        string = str(segment)
        fmt = segment.get_themeattr()
        if prevstr.endswith(("{", "[")):
            # Strip all spaces after "{" / "[".
            string = string.lstrip()
            message.append(ThemeStr(string, fmt))
        elif prevstr.endswith((",", ":")) and string.startswith(" "):
            # Only one space after "," and ":".
            # Squelch whitespace strings into one space.
            string = f" {string.lstrip()}"
            message.append(ThemeStr(string, fmt))
        elif string.startswith(" ") and string.lstrip().startswith(("}", "]")):
            string = string.lstrip()
            message.append(ThemeStr(string, fmt))
        elif prevstr.endswith(" "):
            # Strip all leading spaces.
            string = string.lstrip()

            # Strip all spaces before "}" / "]".
            if string.lstrip().startswith(("}", "]")) and prevstr.endswith(" ") and prevfmt:
                new_prevstr = prevstr.rstrip()
                message = message[:-1]
                message.append(ThemeStr(new_prevstr, prevfmt))
            message.append(ThemeStr(string, fmt))
        else:
            # Just append the segment unmodified.
            message.append(ThemeStr(string, fmt))

        prevstr = string
        prevfmt = fmt

    return message
