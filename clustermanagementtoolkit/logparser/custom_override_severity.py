# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Override message severities using the supplied ruleset.
"""

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name
from clustermanagementtoolkit.cmttypes import name_to_loglevel

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_to_string

from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration


# pylint: disable-next=too-many-branches
def custom_override_severity(message: str | list[ThemeRef | ThemeStr],
                             severity: LogLevel,
                             **kwargs: Any) -> tuple[LogLevel, str | list[ThemeRef | ThemeStr]]:
    """
    Override the message severity if the message matches the provided ruleset.

        Parameters:
            message (str|ThemeArray): The string to override severity for
            severity (LogLevel): The log severity
            **kwargs (dict[str, Any]): Keyword arguments
                options ([dict[str, str]): An array of options
                    severity ([str, str]): An array of severity-related options
                        overrides ([dict[str, Any]]): A list of overrides
                            matchtype (str): The type of match; must be one of:
                                             - "contains"
                                             - "endswith"
                                             - "exact"
                                             - "regex"
                                             - "startswith"
                            matchkey (str): The key (either a plain string or a regular expression)
                                            to use when matching
                            loglevel (str): The loglevel to return if the condition matches
        Returns:
            (LogLevel, str|ThemeArray):
    """
    overrides: list[dict] = deep_get(kwargs, DictPath("options#severity#overrides"), [])

    if not LogparserConfiguration.override_severity:
        return severity, message

    if isinstance(message, list):
        tmp_message = themearray_to_string(message)
    else:
        tmp_message = message
    override_message = message

    for override in overrides:
        override_type = deep_get(override, DictPath("matchtype"), "")
        override_pattern = deep_get(override, DictPath("matchkey"), "")
        override_loglevel = name_to_loglevel(deep_get(override, DictPath("loglevel"), ""))

        if override_type == "startswith":
            if not tmp_message.startswith(override_pattern):
                continue
        elif override_type == "endswith":
            if not tmp_message.endswith(override_pattern):
                continue
        elif override_type == "contains":
            if override_pattern not in tmp_message:
                continue
        elif override_type == "exact":
            if override_pattern != tmp_message:
                continue
        elif override_type == "regex":
            if override_pattern.match(tmp_message) is None:
                continue
        else:
            errmsg = [
                [("Unknown override_type “", "error"),
                 (f"{override_type}", "argument"),
                 ("“", "error")]
            ]
            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
            continue

        severity = override_loglevel

        if isinstance(message, list):
            override_message = []
            severity_name = f"severity_{loglevel_to_name(override_loglevel).lower()}"
            for substring in message:
                if isinstance(substring, ThemeRef):
                    override_message.append(substring)
                else:
                    override_message.append(ThemeStr(substring.string,
                                                     ThemeAttr("logview", severity_name)))
        break

    return severity, override_message
