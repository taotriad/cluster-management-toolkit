# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import difflib
import json
import re
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtio_yaml import json_dumps
from clustermanagementtoolkit.cmtio_yaml import json_loads

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import loglevel_to_name

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.logparser.split_json_style_raw import split_json_style_raw


# pylint: disable-next=too-many-locals,too-many-branches
def json_event(message: str,
               **kwargs: Any) -> tuple[str, LogLevel, list[ThemeRef | ThemeStr] | str,
                                       list[tuple[list[ThemeRef | ThemeStr], LogLevel]]]:
    """
    Given a string, extract any events in JSON format.

        Parameters:
            message (str): The message to format
            **kwargs (dict[str, Any]): Keyword arguments
                severity (LogLevel): The log severity
                facility (str): The log facility
                fold_msg (bool): Should the message be expanded or folded?
                options (dict): Additional, rule specific, options
        Returns:
            (str, LogLevel, ThemeArray, [(ThemeArray, LogLevel)]):
                (str): The facility of the message
                (LogLevel): The LogLevel of the message
                (ThemeArray): The formatted message
                ([(ThemeArray, LogLevel)]):
                    (ThemeArray): The formatted strings of the remnant
                    (LogLevel): The severity of the remnant
    """
    severity: LogLevel = deep_get(kwargs, DictPath("severity"), LogLevel.INFO)
    facility: str = deep_get(kwargs, DictPath("facility"), "")
    fold_msg: bool = deep_get(kwargs, DictPath("fold_msg"), True)
    options: dict = deep_get(kwargs, DictPath("options"), {})

    new_message: str | list[ThemeRef | ThemeStr] = []
    remnants: list[tuple[list[ThemeRef | ThemeStr], LogLevel]] = []
    tmp: list[str] = message.split(" ", 2)

    if not message.startswith("EVENT ") or len(tmp) < 3:
        return facility, severity, message, remnants

    event = tmp[1]

    if event in ("AddPod", "DeletePod", "AddNamespace", "AddNetworkPolicy", "DeleteNamespace") \
            or (event in ("UpdatePod", "UpdateNamespace") and "} {" not in tmp[2]):
        msg = tmp[2]
        _facility, _severity, _message, remnants = \
            split_json_style_raw(message=msg, severity=severity, facility=facility,
                                 fold_msg=fold_msg, options=options, merge_msg=True)
        new_message = [ThemeStr(f"{tmp[0]} {event}", ThemeAttr("logview", "severity_info"))]
        if event in ("UpdatePod", "UpdateNamespace"):
            severity_name = f"severity_{loglevel_to_name(severity).lower()}"
            new_message = [ThemeStr(f"{tmp[0]} {event}", ThemeAttr("logview", severity_name)),
                           ThemeStr(" [No changes]", ThemeAttr("logview", "unchanged"))]
    elif event in ("UpdatePod", "UpdateNamespace"):
        severity_name = f"severity_{loglevel_to_name(severity).lower()}"
        if (re_tmp := re.match(r"^({.*})\s*({.*})", tmp[2])) is not None:
            try:
                old = json_loads(re_tmp[1])
            except (ValueError, json.decoder.JSONDecodeError):
                new_message = \
                    [ThemeStr(f"{tmp[1]} {event}", ThemeAttr("logview", severity_name)),
                     ThemeStr(" [error: could not parse json]",
                              ThemeAttr("logview", "severity_error"))]
                remnants = [([ThemeStr(tmp[2], ThemeAttr("logview", severity_name))], severity)]
                return facility, severity, new_message, remnants

            old_str = json_dumps(old)
            try:
                new = json_loads(re_tmp[2])
            except (ValueError, json.decoder.JSONDecodeError):
                new_message = [ThemeStr(f"{tmp[0]} {event}",
                                        ThemeAttr("logview", severity_name)),
                               ThemeStr(" [error: could not parse json]",
                                        ThemeAttr("logview", "severity_error"))]
                remnants = [([ThemeStr(tmp[2], ThemeAttr("logview", severity_name))], severity)]
                return facility, severity, new_message, remnants
            new_str = json_dumps(new)

            y = 0
            for el in difflib.unified_diff(old_str.split("\n"), new_str.split("\n"),
                                           n=sys.maxsize, lineterm=""):
                y += 1
                if y < 4:
                    continue
                if el.startswith("+"):
                    remnants.append(([ThemeStr(el, ThemeAttr("logview", "severity_diffplus"))],
                                     LogLevel.DIFFPLUS))
                elif el.startswith("-"):
                    remnants.append(([ThemeStr(el, ThemeAttr("logview", "severity_diffminus"))],
                                     LogLevel.DIFFMINUS))
                else:
                    remnants.append(([ThemeStr(el, ThemeAttr("logview", "severity_diffsame"))],
                                     LogLevel.DIFFSAME))
            new_message = [ThemeStr(f"{tmp[0]} {event}", ThemeAttr("logview", severity_name)),
                           ThemeStr(" [State modified]", ThemeAttr("logview", "modified"))]
    else:
        errmsg = [
            [("Unknown EVENT type: ", "default"),
             (f"{event}", "argument")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        return facility, severity, message, remnants

    return facility, severity, new_message, remnants
