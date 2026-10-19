# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


def format_key_value(key: str, value: str,
                     severity: LogLevel, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a key, value, and severity, return a formatted ThemeArray.

        Parameters:
            key (str): The key to format
            value (str): The value to format
            severity (LogLevel): The LogLevel to use when forcing severity
            **kwargs (dict[str, Any]): Keyword arguments
                force_severity (bool): Override default formatting; use severity instead
                error_keys ((str, ...)): A tuple of keys that should be formatted as errors
                allow_bare_keys (str): Should keys without a value be accepted?
                                       all
                                       lowercase
                                       uppercase
                                       capitalize
                                       ""
        Returns:
            (ThemeArray): The formatted message
    """
    force_severity = deep_get(kwargs, DictPath("force_severity"), False)
    error_keys = deep_get(kwargs, DictPath("error_keys"), ("error", "err"))
    severity_name = f"severity_{loglevel_to_name(severity).lower()}"
    value_format = deep_get(kwargs, DictPath("value_format"), ThemeAttr("logview", severity_name))
    tmp: list[ThemeRef | ThemeStr]

    separator = [ThemeRef("separators", "keyvalue_log")]
    if key in error_keys:
        tmp = [ThemeStr(f"{key}", ThemeAttr("types", "key_error"))] \
            + separator \
            + [ThemeStr(f"{value}", value_format)]
    elif force_severity:
        tmp = [ThemeStr(f"{key}", ThemeAttr("types", "key"))] \
            + separator \
            + [ThemeStr(f"{value}", value_format)]
    else:
        tmp = [ThemeStr(f"{key}", ThemeAttr("types", "key"))]
        if value is not None:
            tmp += separator \
                + [ThemeStr(f"{value}", ThemeAttr("types", "value"))]
    return tmp
