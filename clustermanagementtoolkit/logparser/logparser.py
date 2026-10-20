# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Parse a line of log.
"""

from datetime import datetime
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_len

from clustermanagementtoolkit.logparser.logparser_types import LogBlock
from clustermanagementtoolkit.logparser.logparser_types import Parser
from clustermanagementtoolkit.logparser.parsing_multiplexer import parsing_multiplexer
from clustermanagementtoolkit.logparser.split_iso_timestamp import split_iso_timestamp


# pylint: disable-next=too-many-locals
def logparser(**kwargs: Any) -> tuple[datetime, str, LogLevel,
                                      list[ThemeRef | ThemeStr],
                                      list[tuple[list[ThemeRef | ThemeStr], LogLevel]], LogBlock]:
    """
    This is used when the parser is already initialised.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                parser (Parser): The parser to use
                message (str): A line to parse
                fold_msg (bool): Should the message be folded (unmodified)
                                 or unfolded (expanded to multiple lines where possible)
                line (int): The line number
        Returns:
            (datetime, str, LogLevel, str, [(ThemeArray, LogLevel)], LogBlock):
                (datetime): A timestamp
                (str): The log facility
                (LogLevel): Loglevel
                (rstr): An unformatted string
                ([(ThemeArray, LogLevel)]): Formatted remainders with severity
                (LogBlock): Block processing instructions
    """
    parser: Parser | None = deep_get(kwargs, DictPath("parser"))
    message: str = deep_get(kwargs, DictPath("message"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    line: int = deep_get(kwargs, DictPath("line"), 0)
    # First extract the Kubernetes timestamp
    timestamp, message = split_iso_timestamp(message, none_timestamp())

    if parser is None:
        raise ValueError("logparser() called with parser == None")

    options = {
        "__line": line,
    }
    facility, severity, rmessage, remnants, block = \
        parsing_multiplexer(message, filters=parser.rules, fold_msg=fold_msg, options=options)

    max_untruncated_len = 16384
    if isinstance(rmessage, list) and themearray_len(rmessage) > max_untruncated_len - 1:
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        remnants = [([ThemeStr(message[0:max_untruncated_len - 1],
                               ThemeAttr("logview", severity_name))], severity)]
        severity = LogLevel.ERR
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        rmessage = [ThemeStr(f"Line too long ({len(message)} bytes); "
                             f"truncated to {max_untruncated_len} bytes "
                             "(Use line wrapping to see the entire message)",
                             ThemeAttr("logview", severity_name))]

    if rmessage is None:
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        rmessage = [ThemeStr(message, ThemeAttr("logview", severity_name))]
        errmsg = [
            [("Message ", "default"),
             (f"{message}", "argument"),
             ("not parsed; converting.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.INFO, msg=unformatted_msg, messages=formatted_msg)
    elif isinstance(rmessage, str):
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        rmessage = [ThemeStr(rmessage, ThemeAttr("logview", severity_name))]
        errmsg = [
            [("Unexpected format for message: ", "default"),
             (f"{rmessage}", "argument"),
             (" (expected one of [ThemeStr] or tuple(block); converting.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)
    if not (isinstance(rmessage, list) and len(rmessage) and isinstance(rmessage[0], ThemeStr)
            or isinstance(rmessage, tuple)):
        errmsg = [
            [("Unexpected format for rmessage: ", "default"),
             (f"{rmessage}", "argument"),
             (" (expected one of [ThemeStr] or tuple(block).", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.WARNING, msg=unformatted_msg, messages=formatted_msg)

    return timestamp, facility, severity, rmessage, remnants, block
