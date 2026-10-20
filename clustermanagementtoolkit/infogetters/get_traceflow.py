# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An infogetter for traceflow log entries.
"""

from datetime import datetime, UTC
from typing import Any

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_len


# pylint: disable-next=unused-argument,too-many-locals
def get_traceflow(obj: dict, **kwargs: Any) -> \
        tuple[list[datetime], list[str | tuple[str, str]], list[LogLevel],
              list[list[ThemeRef | ThemeStr] | str]]:
    """
    Extract log entries from a traceflow.

        Parameters:
            obj (dict): The object to extract log entries from
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            (([datetime], [str], [str], [str])):
                ([str]): A list of timestamps
                ([str|(str, str)]): A list of facilities
                ([str]): A list of severities
                ([ThemeArray]|str): A list of ThemeArrays
    """
    timestamps: list[datetime] = []
    facilities: list[str | tuple[str, str]] = []
    severities: list[LogLevel] = []
    messages: list[list[ThemeRef | ThemeStr] | str] = []

    for result in deep_get(obj, DictPath("status#results"), []):
        node = deep_get(result, DictPath("node"), "<unset>")
        nodestr_len = len(node) + themearray_len([ThemeRef("separators", "facility_prefix"),
                                                  ThemeRef("separators", "facility_suffix"),
                                                  ThemeRef("separators", "facility_padding")])
        tmp_timestamp = deep_get(result, DictPath("timestamp"), -1)
        if tmp_timestamp >= 0:
            saved_timestamp = datetime.fromtimestamp(tmp_timestamp, tz=UTC)
        else:
            saved_timestamp = none_timestamp()
        message: list[ThemeRef | ThemeStr] = []
        for observation in deep_get(result, DictPath("observations"), []):
            facility = node
            timestamp = saved_timestamp
            for key, value in sorted(observation.items()):
                facilities.append(facility)
                timestamps.append(timestamp.astimezone())
                message = []
                if not facility and node:
                    message.append(ThemeStr("".ljust(nodestr_len), ThemeAttr("main", "default")))
                message += [
                    ThemeStr(key, ThemeAttr("types", "yaml_key")),
                    ThemeRef("separators", "yaml_key_separator"),
                    ThemeRef("separators", "space"),
                    ThemeStr(value, ThemeAttr("types", "yaml_value")),
                ]
                messages.append(message)
                facility = ""
                timestamp = none_timestamp()

    return timestamps, facilities, severities, messages
