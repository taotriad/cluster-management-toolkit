# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An infogetter that returns log entries from journalctl.
"""

from collections.abc import Sequence
from datetime import datetime, UTC
import json
from typing import Any

from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit.cmtlib import none_timestamp

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

import clustermanagementtoolkit.logparser as logparsers


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_journalctl_log(obj: dict, **kwargs: Any) -> \
        tuple[list[datetime], list[str | tuple[str, str] | None], list[LogLevel],
              list[str | Sequence[ThemeRef | ThemeStr]]]:
    """
    Extract log entries from journalctl.

        Parameters:
            obj (dict): The object to extract log entries from
            **kwargs (dict[str, Any]): Keyword arguments
                _show_raw (bool): Return unformatted entries?
        Returns:
            (([datetime], [str], [LogLevel], [ThemeRef|ThemeStr])):
                ([datetime]): A list of timestamps
                ([str|(str, str)]): A list of facilities
                ([LogLevel]): A list of severities
                ([[ThemeRef|ThemeStr]|str]): A list of messages
    """
    timestamps: list[datetime] = []
    facilities: list[str | tuple[str, str] | None] = []
    severities: list[LogLevel] = []
    messages: list[str | Sequence[ThemeRef | ThemeStr]] = []

    show_raw: bool = deep_get(kwargs, DictPath("_show_raw"), False)
    objlist = deep_get(obj, DictPath("obj"))
    parser = deep_get(objlist[0], DictPath("parser"))

    for line in objlist[1:]:
        try:
            d = json_loads(line)
        except (ValueError, json.decoder.JSONDecodeError):
            d = {}

        timestamp = \
            datetime.fromtimestamp(int(deep_get(d, DictPath("__REALTIME_TIMESTAMP")), 0) / 1000000,
                                   tz=UTC)
        severity = LogLevel.DEFAULT
        facility = None
        remnants = None
        msg: str | Sequence[ThemeRef | ThemeStr] = ""

        raw_severity: LogLevel = LogLevel(int(deep_get(d, DictPath("PRIORITY"), "6")))
        raw_msg = deep_get(d, DictPath("MESSAGE"), "")

        if show_raw:
            msg = raw_msg
        elif parser == "glog":
            msg, severity, facility, remnants, matched = \
                logparsers.split_glog(raw_msg, severity=raw_severity)

            if not matched:
                severity = raw_severity
                remnants = None
                msg = raw_msg
        elif "=" in raw_msg and parser == "key_value":
            facility, severity, msg, remnants = \
                logparsers.key_value(raw_msg, severity=raw_severity, fold_msg=False)
        elif raw_msg.startswith("{\"") and raw_msg.endswith("\"}"):
            facility, severity, msg, remnants = \
                logparsers.split_json_style(raw_msg, severity=raw_severity, fold_msg=False)
        else:
            severity = raw_severity
            msg = raw_msg

        # If this is dmesg we try to extract the facility
        if isinstance(msg, str) and deep_get(d, DictPath("SYSLOG_IDENTIFIER")) == "kernel":
            facility_msg_split = msg.split(": ", maxsplit=1)
            if len(facility_msg_split) == 2:
                facility, msg = facility_msg_split

        severity_overrides: dict[str, LogLevel] = {
            "segfault at": LogLevel.WARNING,    # Normally info
        }

        for severity_match, severity_override in severity_overrides.items():
            if severity_match in msg:
                severity = severity_override

        timestamps.append(timestamp.astimezone())
        facilities.append(facility)
        if severity == LogLevel.DEFAULT:
            severity = raw_severity
        severities.append(severity)
        messages.append(msg)

        if remnants is not None:
            if isinstance(remnants, tuple):
                fmt_remnants, remnant_severity = remnants

                for remnant in fmt_remnants:
                    timestamps.append(none_timestamp())
                    facilities.append("")
                    severities.append(remnant_severity)
                    messages.append(remnant)
            else:
                for remnant, remnant_severity in remnants:
                    timestamps.append(none_timestamp())
                    facilities.append("")
                    severities.append(remnant_severity)
                    messages.append(remnant)

    return timestamps, facilities, severities, messages
