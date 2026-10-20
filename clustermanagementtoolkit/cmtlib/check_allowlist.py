# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check whether the provided value is in the allowlist,
and either return a default, or exit if it's not in the allowlist.
"""

import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import LogLevel


# pylint: disable=too-many-arguments,too-many-positional-arguments
def check_allowlist(allowlist: dict, allowlist_name: str, value: Any | None,
                    default: Any | None = None, exit_on_fail: bool = True,
                    allow_none: bool = False) -> Any | None:
    """
    Check whether the provided value is in the allowlist,
    and either return a default, or exit if it's not in the allowlist.

        Parameters:
            allowlist (dict[str, Any]): A list of allowed values and the corresponding return value
            allowlist_name (str): The name of the allow list (used for exit message)
            value (Any): A value that can be used as a dict key
            default (Any): The value to return if the value isn't in the allow list
            exit_on_fail (bool): Exit on failure
            allow_none (bool): Allow None as value
        Returns:
            (Any): An acceptable value
    """
    if value is None and allow_none:
        return None

    if callable(value) and value.__name__ in allowlist:
        return value

    if value not in allowlist and exit_on_fail:
        errmsg = [
            [(f"{value}", "argument"),
             (" is not in allowlist ", "default"),
             (f"{allowlist_name}", "argument"),
             ("; aborting.", "default")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        sys.exit(unformatted_msg)

    return allowlist.get(value, default)
