# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format the output from Go events.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.reformat_message_remnants import reformat_message_remnants


# pylint: disable-next=too-many-branches,too-many-statements,too-many-locals
def expand_event_objectmeta(message: str, severity: LogLevel, **kwargs: Any) \
        -> tuple[LogLevel,
                 str | list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Given a log message, expand and format objectmeta event messages.

        Parameters:
            message (str): The log message
            severity (LogLevel): Current loglevel; will be overriden if new severity is higher
            **kwargs (dict[str, Any]): Keyword arguments
                remnants ([(ThemeArray, LogLevel)]): Remnants for messages split into multiple lines
                fold_msg (bool): Should lines be unfolded where possible?
        Returns:
            (LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]):
                (LogLevel): The new loglevel
                (str|ThemeArray): The processed message
                ([(ThemeArray, LogLevel)]): The formatted remnants
    """
    remnants: list[tuple[list[ThemeRef | ThemeStr],
                         LogLevel]] = deep_get(kwargs, DictPath("remnants"), [])
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)

    raw_message = message
    curlydepth = 0

    # This just makes sure that the indentation matches up
    for i in range(len(raw_message)):
        if message[i] == "{":
            curlydepth += 1
        elif message[i] == "}":
            curlydepth -= 1
            if curlydepth < 0:
                # Abort parsing; assume that this message is either malformed
                # or that the parser is flawed
                return severity, message, remnants

    new_message: list[ThemeRef | ThemeStr] = []
    indent = 2
    depth = 0
    escaped = False
    tmp = ""

    # For the sake of simplicity, indent the text before we try to format it.
    for i, raw_msg in enumerate(raw_message):
        if raw_msg == "\"" and not escaped:
            tmp += raw_msg
            continue
        if raw_msg == "\\":
            escaped = not escaped
            tmp += raw_msg
            continue
        if raw_msg == "{":
            depth += 1
            tmp += f"{raw_msg}\n{''.ljust(indent * depth)}"
            continue
        if raw_msg == ",":
            if tmp.rstrip().endswith("}"):
                tmp = tmp.rstrip()
            tmp += f"{raw_msg}\n{''.ljust(indent * depth)}"
            continue
        if raw_msg == "}":
            depth -= 1
            if tmp.rstrip().endswith(","):
                tmp = tmp.rstrip()
            tmp += f"\n{''.ljust(indent * depth)}{raw_msg}"
            continue
        tmp += raw_msg

    inside_objectmeta = False

    for line in tmp.splitlines():
        if line.strip().startswith("ObjectMeta"):
            remnants.append(([ThemeStr(line, ThemeAttr("types", "yaml_key"))], severity))
            inside_objectmeta = True
            continue
        if inside_objectmeta and "}" in line:
            inside_objectmeta = False
        if ":" in line and not inside_objectmeta:
            key, value = line.split(":", 1)
            remnants.append(([ThemeStr(key, ThemeAttr("types", "yaml_key")),
                              ThemeRef("separators", "yaml_key_separator"),
                              ThemeStr(f"{value}", ThemeAttr("types", "yaml_value"))], severity))
        elif inside_objectmeta:
            remnants.append(([ThemeStr(line, ThemeAttr("types", "yaml_value"))], severity))
        else:
            remnants.append(([ThemeStr(line, ThemeAttr("types", "yaml_key"))], severity))

    new_message, remnants = reformat_message_remnants("", remnants, severity)

    if fold_msg:
        new_message = fold_message_with_remnants(new_message, remnants, severity)
        remnants = []

    return severity, new_message, remnants
