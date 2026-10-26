# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Split messages in JSON or JSON-resembling formats,
without any reformatting rules applied.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.merge_message import merge_message
from clustermanagementtoolkit.logparser.split_json_style import split_json_style


# pylint: disable-next=too-many-locals
def split_json_style_raw(message: str, **kwargs: Any) \
        -> tuple[str, LogLevel, str, list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Split JSON style messages.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                fold_msg (bool): [unused]
                options (dict): Additional, rule specific, options
        Returns:
            (str|ThemeArray, LogLevel, str, [(ThemeArray, LogLevel)]):
                (str|ThemeArray): The untouched or formatted message
                (LogLevel): The LogLevel of the message
                (str): The facility of the message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    options: dict = deep_get(kwargs, DictPath("options"), {})
    merge_msg: bool = deep_get(kwargs, DictPath("merge_msg"), False)

    tmp_msg_first = LogparserConfiguration.msg_first
    tmp_msg_extract = LogparserConfiguration.msg_extract
    tmp_pop_severity = LogparserConfiguration.pop_severity
    tmp_pop_ts = LogparserConfiguration.pop_ts
    tmp_pop_facility = LogparserConfiguration.pop_facility

    LogparserConfiguration.msg_first = False
    LogparserConfiguration.msg_extract = False
    LogparserConfiguration.pop_severity = False
    LogparserConfiguration.pop_ts = False
    LogparserConfiguration.pop_facility = False

    _facility, _severity, _message, _remnants = \
        split_json_style(message=message, severity=severity,
                         facility=facility, fold_msg=fold_msg, options=options)

    LogparserConfiguration.msg_first = tmp_msg_first
    LogparserConfiguration.msg_extract = tmp_msg_extract
    LogparserConfiguration.pop_severity = tmp_pop_severity
    LogparserConfiguration.pop_ts = tmp_pop_ts
    LogparserConfiguration.pop_facility = tmp_pop_facility

    if merge_msg:
        message, remnants = merge_message(message, remnants=_remnants, severity=severity)
    else:
        remnants = _remnants

    if severity is None:
        severity = _severity
    if facility == "":
        facility = _facility

    return facility, severity, message, remnants
