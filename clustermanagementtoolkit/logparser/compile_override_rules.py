# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def compile_override_rules(parser_file: str,
                           override_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Given a list of override-rules, format it for use in parser-rules.

        Parameters:
            parser_file (str): The parser-file that the rule originated from
            override_rules ([dict[str, Any]]): The override-rules to format
        Returns:
            ([dict[str, Any]]): The formatted override-rules
    """
    overrides = []

    for override in override_rules:
        matchtype = deep_get(override, DictPath("matchtype"))
        matchkey = deep_get(override, DictPath("matchkey"))
        _loglevel = deep_get(override, DictPath("loglevel"))

        if matchtype is None or matchkey is None or _loglevel is None:
            errmsg = [
                [("Incorrect override rule in Parser ", "default"),
                 (f"{parser_file}", "argument"),
                 ("; every override must define ", "default"),
                 ("matchtype, matchkey, and loglevel", "default")],
            ]
            unformatted_msg, formatted_msg = \
                ANSIThemeStr.format_error_msg(errmsg)
            cmtlog.log(LogLevel.ERR,
                       msg=unformatted_msg, messages=formatted_msg)
            continue

        if matchtype == "regex":
            regex = deep_get(override, DictPath("matchkey"), "")
            matchkey = re.compile(regex)
        overrides.append({
            "matchtype": matchtype,
            "matchkey": matchkey,
            "loglevel": _loglevel,
        })

    return overrides
