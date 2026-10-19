# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.kubernetes_resources import event_reasons

from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.reformat_message_remnants import reformat_message_remnants


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def expand_event(message: str, severity: LogLevel, **kwargs: Any) \
        -> tuple[LogLevel, list[ThemeRef | ThemeStr] | str,
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Given a log message, expand and format event messages.

        Parameters:
            message (str): The log message
            severity (LogLevel): Current loglevel; will be overriden if new severity is higher
            **kwargs (dict[str, Any]): Keyword arguments
                remnants ([(ThemeArray, LogLevel)]): Remnants for messages split into multiple lines
                fold_msg (bool): Should lines be unfolded where possible?
        Returns:
            (LogLevel, str, [(ThemeArray, LogLevel)]):
                (LogLevel): The new loglevel
                (str): The processed message
                ([(ThemeArray, LogLevel)]): The formatted remnants
    """
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = \
        deep_get(kwargs, DictPath("remnants"), [])
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)

    # If we already have remnants we're unlikely to be able to do anything useful.
    # This should never happen in practice though.
    if remnants:
        return severity, message, remnants

    raw_message = message
    parendepth = 0
    curlydepth = 0
    eventstart = 0
    eventend = 0
    refstart = 0
    refend = 0

    for i in range(len(raw_message)):
        if message[i] == "(":
            parendepth += 1
            if eventstart is None:
                eventstart = i + 1
        elif message[i] == "{":
            curlydepth += 1
            if not refstart:
                refstart = i + 1
        elif message[i] == "}":
            curlydepth -= 1
            if curlydepth < 0:
                # Abort parsing; assume that this message is either malformed
                # or that the parser is flawed
                return severity, message, remnants
            refend = i
        elif message[i] == ")":
            parendepth -= 1
            if not parendepth:
                if curlydepth:
                    # Abort parsing; assume that this message is either malformed
                    # or that the parser is flawed
                    return severity, message, remnants

                eventend = i
                break

    message = raw_message[0:eventstart]
    indent = 2
    type_format = ThemeAttr("main", "status_unknown")
    # Try to extract an embedded severity; use it if higher than severity
    re_tmp = re.match(r"^.*(type: ')([A-Z][a-z]+)(' reason: ')([A-Za-z][A-Za-z-.]+)('.*)",
                      raw_message)
    if re_tmp is not None:
        _severity = severity
        if re_tmp[2] == "Normal":
            _severity = LogLevel.INFO
            type_format = ThemeAttr("main", "status_ok")
        elif re_tmp[2] == "Warning":
            _severity = LogLevel.WARNING
            type_format = ThemeAttr("main", "status_admin")
        severity = min(severity, _severity)
    remnants.append(([ThemeStr(raw_message[eventstart:refstart],
                               ThemeAttr("types", "yaml_reference"))], severity))

    for i, _key_value in enumerate(raw_message[refstart:refend].split(", ")):
        key, value = _key_value.split(":", 1)
        remnant: list[ThemeRef | ThemeStr] = \
            [ThemeStr(" ".ljust(indent * 2) + key, ThemeAttr("types", "yaml_key")),
             ThemeRef("separators", "yaml_key_separator"),
             ThemeStr(f" {value}", ThemeAttr("types", "yaml_value"))]
        if i + 1 < len(raw_message[refstart:refend].split(", ")):
            remnant += [ThemeStr(",", ThemeAttr("types", "yaml_list"))]
        remnants.append((remnant, severity))
    remnants.append(([ThemeStr(" ".ljust(indent * 1) + raw_message[refend:eventend],
                               ThemeAttr("types", "yaml_reference"))], severity))
    severity_name = f"severity_{loglevel_to_name(severity).lower()}"
    message_format = ThemeAttr("logview", severity_name)
    if re_tmp is not None:
        reason_format = deep_get(event_reasons, DictPath(re_tmp[4]),
                                 ThemeAttr("logview", severity_name))
        remnants.append(([ThemeStr(raw_message[eventend:eventend + 3],
                                   ThemeAttr("types", "yaml_reference")),
                          ThemeStr(re_tmp[1], message_format),
                          ThemeStr(re_tmp[2], type_format),
                          ThemeStr(re_tmp[3], message_format),
                          ThemeStr(re_tmp[4], reason_format),
                          ThemeStr(re_tmp[5], message_format)], severity))
    else:
        remnants.append(([ThemeStr(raw_message[eventend:eventend + 3],
                                   ThemeAttr("types", "yaml_reference")),
                          ThemeStr(raw_message[eventend + 3:len(raw_message)],
                                   message_format)], severity))

    new_message, remnants = reformat_message_remnants(message, remnants, severity)

    if fold_msg:
        new_message = fold_message_with_remnants(new_message, remnants, severity)
        remnants = []

    return severity, new_message, remnants
