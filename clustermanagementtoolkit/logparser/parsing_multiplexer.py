# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
The main loop of the logparser.
"""

import sys
from typing import Any

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.custom_line import custom_line
from clustermanagementtoolkit.logparser.custom_override_severity import custom_override_severity
from clustermanagementtoolkit.logparser.custom_splitter import custom_splitter
from clustermanagementtoolkit.logparser.directory import directory
from clustermanagementtoolkit.logparser.expand_event import expand_event
from clustermanagementtoolkit.logparser.expand_event_objectmeta import expand_event_objectmeta
from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.http import http
from clustermanagementtoolkit.logparser.iptables import iptables
from clustermanagementtoolkit.logparser.json_event import json_event
from clustermanagementtoolkit.logparser.key_value import key_value
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.logparser.key_value_with_leading_message import key_value_with_leading_message  # noqa: E501
from clustermanagementtoolkit.logparser.logparser_types import LogBlock
from clustermanagementtoolkit.logparser.logparser_types import ParserRule
from clustermanagementtoolkit.logparser.merge_message import merge_message
from clustermanagementtoolkit.logparser.modinfo import modinfo
from clustermanagementtoolkit.logparser.seconds_severity_facility import seconds_severity_facility
from clustermanagementtoolkit.logparser.split_bracketed_severity import split_bracketed_severity
from clustermanagementtoolkit.logparser.split_glog import split_glog
from clustermanagementtoolkit.logparser.strip_iso_timestamp import strip_iso_timestamp
from clustermanagementtoolkit.logparser.sysctl import sysctl
from clustermanagementtoolkit.logparser.split_json_style import split_json_style
from clustermanagementtoolkit.logparser.tab_separated import tab_separated


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def parsing_multiplexer(message: str | list[ThemeRef | ThemeStr],
                        filters: list[ParserRule], **kwargs: Any) \
        -> tuple[str, LogLevel,
                 list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]], LogBlock]:
    """
    The main loop for the parser; it will iterate loop through all rules specified for
    a particular log until a line has been fully processed.

        Parameters:
            message (str): The message to format
            filters ([ParserRule]): The list of parser-rules to apply
            **kwargs (dict[str, Any]): Keyword arguments
                fold_msg (bool): Should the message be expanded or folded?
                options (dict[str, Any]): Options to pass to the block parsers
        Returns:
            (str, LogLevel, [ThemeArray], [(ThemeArray, LogLevel)], dict):
                (str): The log facility
                (LogLevel): The log severity
                (ThemeArray): A formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
                (LogBlock): Block processing instructions
    """
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    options: dict = deep_get(kwargs, DictPath("options"), {})

    facility: str = ""
    severity: LogLevel = LogLevel.DEFAULT
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []
    processor: LogBlock = {}

    # pylint: disable-next=too-many-nested-blocks
    for _filter, filter_options in filters:
        try:
            filter_options = {**filter_options, **options}
        except TypeError:
            sys.exit(f"Incompatible filter-options:\n{_filter=}\n{filter_options=}")
        # These parsers CANNOT handle ThemeArrays
        if isinstance(message, str):
            # Multiparsers
            if _filter == "glog":
                facility, severity, message, remnants, _match = \
                    split_glog(message, severity=severity, facility=facility)
            elif _filter == "directory":
                facility, severity, message, remnants = \
                    directory(message, fold_msg=fold_msg, severity=severity, facility=facility)
            elif _filter == "seconds_severity_facility":
                facility, severity, message, remnants = \
                    seconds_severity_facility(message, fold_msg=fold_msg)
            elif _filter == "expand_event":
                if message.startswith("Event(v1.ObjectReference{"):
                    severity, message, remnants = \
                        expand_event(message, severity=severity,
                                     remnants=remnants, fold_msg=fold_msg)
                elif message.startswith("&Event{ObjectMeta:"):
                    severity, message, remnants = \
                        expand_event_objectmeta(message, severity=severity,
                                                remnants=remnants, fold_msg=fold_msg)
            elif _filter == "modinfo":
                facility, severity, message, remnants = modinfo(message, fold_msg=fold_msg)
            elif _filter == "sysctl":
                facility, severity, message, remnants = \
                    sysctl(message, severity=severity, facility=facility, fold_msg=fold_msg)
            elif _filter == "custom_splitter":
                facility, severity, message = \
                    custom_splitter(message, severity=severity, facility=facility,
                                    fold_msg=fold_msg, options=filter_options)
            elif _filter == "http":
                facility, severity, message = \
                    http(message, severity=severity, facility=facility,
                         fold_msg=fold_msg, options=filter_options)
            elif _filter == "iptables":
                facility, severity, message, remnants = \
                    iptables(message, remnants, severity=severity,
                             facility=facility, fold_msg=fold_msg)
            elif _filter == "json" and isinstance(message, str):
                _message: list[ThemeRef | ThemeStr] | str = message
                if message.startswith(("{\"", "{ \"")):
                    facility, severity, message, remnants = \
                        split_json_style(message, severity=severity, facility=facility,
                                         fold_msg=fold_msg, options=filter_options)
            elif _filter == "json_with_leading_message" and isinstance(message, str):
                # If the line doesn't end with a "}" it's not JSON.
                if not message.endswith("}"):
                    continue
                parts = message.split("{", 1)
                if len(parts) == 2:
                    # No leading message
                    if not parts[0]:
                        facility, severity, message, remnants = \
                            split_json_style(message, severity=severity, facility=facility,
                                             fold_msg=fold_msg, options=filter_options)
                    elif parts[0].rstrip() != parts[0]:
                        parts[0] = parts[0].rstrip()
                        # It isn't leading message + JSON unless there's whitespace in-between.
                        facility, severity, _message, remnants = \
                            split_json_style("{" + parts[1], severity=severity,
                                             facility=facility, fold_msg=fold_msg,
                                             options=filter_options)
                        if (_severity := severity) is None:
                            _severity = LogLevel.INFO
                        _message, remnants = \
                            merge_message(_message, remnants=remnants, severity=_severity)
                        severity_name = f"severity_{loglevel_to_name(_severity).lower()}"
                        message = [ThemeStr(parts[0], ThemeAttr("logview", severity_name))]
                        if fold_msg:
                            message = fold_message_with_remnants(message, remnants, _severity,
                                                                 pad="message")
                            remnants = []
            elif _filter == "json_event":
                # We do not extract the facility/severity from folded messages,
                # so just skip if fold_msg == True.
                if message.startswith("EVENT ") and not fold_msg:
                    facility, severity, message, remnants = \
                        json_event(message, fold_msg=fold_msg, options=filter_options)
            elif _filter == "key_value" and "=" in message:
                facility, severity, message, remnants = \
                    key_value(message, fold_msg=False, severity=severity,
                              facility=facility, options=filter_options)
                # Fold the message if needed.
                if fold_msg:
                    message = fold_message_with_remnants(message, remnants, severity, pad="all")
                    remnants = []
            elif _filter == "key_value_with_leading_message" and "=" in message:
                facility, severity, message, remnants = \
                    key_value_with_leading_message(message, fold_msg=fold_msg,
                                                   severity=severity, facility=facility,
                                                   options=filter_options)
                # Fold the message if needed.
                if fold_msg:
                    message = fold_message_with_remnants(message, remnants, severity, pad="all")
                    remnants = []
            # Timestamp formats
            elif _filter == "ts_8601":  # Anything that resembles ISO-8601 / RFC 3339
                message = strip_iso_timestamp(message)
            # Severity formats
            elif _filter == "bracketed_severity":
                severity, message = split_bracketed_severity(message, default=filter_options)
            # Filters
            elif _filter == "strip_ansicodes":
                message = cmtlib.strip_ansicodes(message)
            # The content from these rules will typically not be processed further
            elif _filter == "tab_separated":
                facility, severity, message, remnants = \
                    tab_separated(message, severity=severity, facility=facility,
                                  fold_msg=fold_msg, options=filter_options)
            # Block starters; these are parser loop terminators if a match is found.
            elif _filter == "custom_line":
                severity, message, processor = \
                    custom_line(message, fold_msg=fold_msg, severity=severity,
                                options=filter_options)
                if processor:
                    remnants = []
                    break
        # These parsers CAN handle ThemeArrays
        # Severity formats
        if _filter == "override_severity":
            severity, message = custom_override_severity(message, severity, options=filter_options)

        if isinstance(message, tuple) and message[0] == "start_block":
            break

    if severity == LogLevel.DEFAULT:
        severity = LogLevel.INFO

    # As a step towards always using ThemeStr, convert all regular strings
    if isinstance(message, str):
        rmessage: list[ThemeRef | ThemeStr] = \
            [ThemeStr(message, ThemeAttr("logview",
                                         f"severity_{loglevel_to_name(severity).lower()}"))]
    else:
        rmessage = message

    return facility, severity, rmessage, remnants, processor
