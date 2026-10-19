# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import json
from typing import Any

from clustermanagementtoolkit.cmtio_yaml import json_dumps
from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit import formatters

from clustermanagementtoolkit.logparser.fold_message_with_remnants import fold_message_with_remnants
from clustermanagementtoolkit.logparser.is_timestamp import is_timestamp
from clustermanagementtoolkit.logparser.str_to_severity import str_to_severity


# pylint: disable-next=too-many-locals
def tab_separated(message: str, **kwargs: Any) \
        -> tuple[str, LogLevel, str | list[ThemeRef | ThemeStr],
                 list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Extract messages of the format datetime\tSEVERITY\t[facility\t]message[\tjson].

        Parameters:
            message (str): The message to reformat
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The current loglevel
                facility (str): The current facility
                fold_msg (bool): Should the message be expanded or folded?
                options (dict): Additional, rule specific, options
        Returns:
            (facility, severity, message, remnants)
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    options: dict = deep_get(kwargs, DictPath("options"), {})

    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []

    messages: list[str] = deep_get(options, DictPath("message#keys"),
                                   ["msg", "message"])
    errors: list[str] = deep_get(options, DictPath("error#keys"),
                                 ["err", "error"])
    versions: list[str] = deep_get(options, DictPath("version#keys"),
                                   ["Version"])

    fields = message.split("\t")

    # If the first field is not a timestamp
    # we cannot trust the rest of the message to be what we hope for.
    if not is_timestamp(fields[0]) or len(fields) < 3:
        return facility, severity, message, remnants

    severity = str_to_severity(fields[1], default=severity)

    override_formatting: dict[str, Any] = {}
    for _msg in versions:
        override_formatting[f"\"{_msg}\""] = {
            "key": ThemeAttr("types", "yaml_key"),
            "value": ThemeAttr("logview", "severity_notice")
        }
    for _msg in messages:
        override_formatting[f"\"{_msg}\""] = {
            "key": ThemeAttr("types", "yaml_key"),
            "value": ThemeAttr("logview", f"severity_{loglevel_to_name(severity).lower()}")
        }
    for _err in errors:
        override_formatting[f"\"{_err}\""] = {
            "key": ThemeAttr("types", "yaml_key_error"),
            "value": ThemeAttr("logview", f"severity_{loglevel_to_name(severity).lower()}"),
        }

    # If we have 5 fields it's (hopefully) timestamp, severity, facility, message, json;
    # if it's 4, on the other hand, we need to figure out whether it's
    # timestamp, severity, message, json, or timestamp, severity, facility, json.
    #
    # To do this we check the last field to see if it can be parsed as JSON.
    #
    # If it's only 3 fields we assume the third field to be the message.
    if fields[-1].strip().startswith("{") and fields[-1].strip().endswith("}"):
        # This is a promising candidate to be JSON.
        try:
            d = json_loads(fields[-1])
            json_strs = json_dumps(d)
            for remnant in formatters.format_yaml(json_strs,
                                                  override_formatting=override_formatting,
                                                  json=True):
                remnants.append((remnant, severity))
            if len(fields) == 4:
                message = fields[2]
            else:
                facility = fields[2]
                message = fields[3]
            # OK, parsing as JSON was successful. Do we fold it or not?
            if fold_msg:
                new_message = fold_message_with_remnants(f"{message} ", remnants, severity)
                remnants = []
                return facility, severity, new_message, remnants
        except (ValueError, json.decoder.JSONDecodeError):
            # If we failed to decode the message, and there are three fields,
            # they (hopefully) are severity, facility, message.
            # If we failed to decode the message, and there are four fields,
            # it's (probably) invalid JSON.
            facility = fields[2]
            message = " ".join(fields[3:])
    elif len(fields) == 3:
        message = fields[2]
    else:
        facility = fields[2]
        message = " ".join(fields[3:])

    return facility, severity, message, remnants
