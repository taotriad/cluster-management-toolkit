# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any, cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import name_to_loglevel

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.letter_to_severity import letter_to_severity
from clustermanagementtoolkit.logparser.str_3letter_to_severity import str_3letter_to_severity
from clustermanagementtoolkit.logparser.str_4letter_to_severity import str_4letter_to_severity
from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def custom_splitter(message: str, **kwargs: Any) -> \
        tuple[str, LogLevel, list[ThemeRef | ThemeStr] | str]:
    """
    Custom splitter.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                options (dict[str, Any]): splitter options
                    regex (re.Pattern[str]): A compiled regex
                    severity (dict[str, Any]): A dict of severity options
                        field (str): The index of the field to get the severity from
                        transform (str): The rule to use when transforming the severity value;
                                         valid options:
                                         letter, 3letter, 4letter, str, int
                        overrides (list): Special cases for overriding the severity
                    facility (dict[str, Any]): A dict of facility options
                        fields ([int]): A list of indexes for the fields containing the facility
                        separators ([str]): A list of separators to use when joining the facility
                    message (dict[str, Any]): A dict of message options
                        field (str): The index of the field to get the message from
        Returns:
            (str|ThemeArray, LogLevel, str, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (str|ThemeArray): The untouched or formatted message
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.DEFAULT)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    options: dict = deep_get(kwargs, DictPath("options"), {})

    compiled_regex: re.Pattern[str] = deep_get(options, DictPath("regex"))
    severity_field = deep_get(options, DictPath("severity#field"))
    severity_transform = deep_get(options, DictPath("severity#transform"))
    severity_default: str = deep_get(kwargs, DictPath("options#severity#default"), "default")
    severity = name_to_loglevel(severity_default, severity)
    facility_fields: list[int] | None = deep_get(options, DictPath("facility#fields"))
    facility_separators: list[str] = deep_get(options, DictPath("facility#separators"), [""])
    message_field = deep_get(options, DictPath("message#field"))

    # This message is already formatted.
    if isinstance(message, list):
        return facility, severity, message

    # The bare minimum for these rules:
    if not compiled_regex:
        errmsg = [
            [("The parser rule lacks a regular expression.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        return facility, severity, message
    if message_field is None:
        errmsg = [
            [("The parser rule lacks a message field.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        return facility, severity, message

    tmp = compiled_regex.match(message)

    if tmp is not None:
        group_count = len(tmp.groups())
        if message_field > group_count:
            errmsg = [
                [("The parser rule references non-existing capture group ", "default"),
                 (f"{message_field}", "argument"),
                 (" for message; the valid range is [", "default"),
                 ("1", "argument"),
                 ("-", "separator"),
                 (f"{group_count}", "argument"),
                 ("].", "default")],
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            message_field = 0
            severity_field = None
            facility_fields = None
        if severity_field is not None and severity_transform is not None:
            if severity_field > group_count:
                errmsg = [
                    [("The parser rule references non-existing capture group ", "default"),
                     (f"{severity_field}", "argument"),
                     (" for severity; the valid range is [", "default"),
                     ("1", "argument"),
                     ("-", "separator"),
                     (f"{group_count}", "argument"),
                     ("].", "default")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                severity = LogLevel.DEFAULT
            elif severity_transform == "letter":
                severity = letter_to_severity(tmp[severity_field], default=severity)
            elif severity_transform == "3letter":
                severity = str_3letter_to_severity(tmp[severity_field], default=severity)
            elif severity_transform == "4letter":
                severity = str_4letter_to_severity(tmp[severity_field], default=severity)
            elif severity_transform == "str":
                severity = str_to_severity(tmp[severity_field], default=severity)
            elif severity_transform == "int":
                intseverity: int | None = None
                try:
                    intseverity = int(tmp[severity_field])
                except ValueError:
                    errmsg = [
                        [("The parser rule matched a non-integer as severity, but ", "default"),
                         ("uses int as severity transform rule.", "default")],
                    ]
                    unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                    cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                if intseverity:
                    try:
                        severity = LogLevel(intseverity)
                    except ValueError:
                        errmsg = [
                            [("The parser rule matched an integer as severity, but ", "default"),
                             (f"the value {tmp[severity_field]} is out of range.", "default")],
                        ]
                        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            else:
                errmsg = [
                    [("Unknown severity transform rule ", "default"),
                     (f"{severity_transform}", "argument"),
                     ("; could not extract severity.", "default")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                severity = LogLevel.DEFAULT
            severity, message = cast(tuple[LogLevel, str],
                                     custom_override_severity(tmp[message_field],
                                     severity, options=options))
        else:
            message = tmp[message_field]
        if facility_fields and not facility:
            facility = ""
            for i, field in enumerate(facility_fields):
                if field > group_count:
                    errmsg = [
                        [("The parser rule references non-existing capture group ", "default"),
                         (f"{field}", "argument"),
                         (" for facility; the valid range is [", "default"),
                         ("1", "argument"),
                         ("-", "separator"),
                         (f"{group_count}", "argument"),
                         ("].", "default")],
                    ]
                    unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                    cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                    break
                if i:
                    facility += facility_separators[min(i - 1, len(facility_separators) - 1)]
                if field != 0:
                    facility += tmp[field]

    return facility, severity, message
