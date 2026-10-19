# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_set

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.key_value import key_value
from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.merge_message import merge_message


# pylint: disable-next=too-many-locals
def key_value_with_leading_message(message: str, **kwargs: Any) -> \
        tuple[str, LogLevel, str | list[ThemeRef | ThemeStr],
              list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Format a "message key=value" message.

        Parameters:
            message (str): The string to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                options (dict): Additional, rule specific, options
        Returns:
            (str, LogLevel, str|ThemeArray, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The untouched or formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    options: dict = deep_get(kwargs, DictPath("options"), {})
    allow_bare_keys: bool = deep_get(options, DictPath("allow_bare_keys"), "")
    new_message: list[ThemeRef | ThemeStr] | str | None = None

    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    # Split into substrings based on spaces
    tmp: list[str] | None = re.findall(r"(?:\".*?\"|\S)+", message.replace("\\\"", "<<<quote>>>"))
    if tmp:
        # First go through the list of matches and check that there is at least one
        # key=value pair; we do not allow *only* bare keys. While it could theoretically
        # occur, it leaves too much room for false positives.
        # Also check whether the last word ends with a period. In this case we'll assume
        # that this is an informational message rather than a key=value message.
        if message.endswith(".") or not any("=" in item for item in tmp):
            # Give up; this line cannot be parsed as a set of key=value
            return facility, severity, message, remnants

        if "=" in tmp[0]:
            # Try parsing this as regular key_value
            facility, severity, new_message, remnants = \
                key_value(message, severity=severity, facility=facility, options=options)
            return facility, severity, new_message, remnants

        for item in tmp[1:]:
            # we could not parse this as "msg key=value"; give up
            if "=" not in item and (item.endswith(":") or not allow_bare_keys):
                return facility, severity, message, remnants
        rest = message.removeprefix(tmp[0]).lstrip()
        new_message = tmp[0]
        tmp_msg_extract = LogparserConfiguration.msg_extract
        LogparserConfiguration.msg_extract = False

        if "Event" in new_message:
            deep_set(options, DictPath("severity#highlight_reason"), True, create_path=True)
        facility, severity, first_message, tmp_new_remnants = \
            key_value(rest, severity=severity, facility=facility, options=options)
        LogparserConfiguration.msg_extract = tmp_msg_extract
        new_remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]]
        if tmp_new_remnants:
            _message, new_remnants = \
                merge_message(first_message, remnants=tmp_new_remnants, severity=severity)
        else:
            if first_message:
                new_remnants = [(cast(list[ThemeRef | ThemeStr], first_message), severity)]
            else:
                new_remnants = []
        if "FLAG:" in new_message and "FLAG: " in message:
            new_message = fold_message_with_remnants(new_message, new_remnants,
                                                     severity, pad="all")
            new_remnants = []
        return facility, severity, new_message, new_remnants
    return facility, severity, message, remnants
