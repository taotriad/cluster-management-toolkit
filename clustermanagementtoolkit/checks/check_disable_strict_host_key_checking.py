# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtpaths import CMT_CONFIG_FILE

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def check_disable_strict_host_key_checking(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether or not strict host key checking has been disabled in cmtconfig.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                cmtconfig_dict (dict[str, Any]): The cmtconfig file
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                (int): The new count of critical severity security issues
                (int): The new count of error severity security issues
                (int): The new count of warning severity security issues
                (int): The new count of note severity security issues
    """
    cmtconfig_dict: dict[str, Any] = deep_get(kwargs, DictPath("cmtconfig_dict"), {})
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)

    abort = False

    ansithemeprint([ANSIThemeStr("[Checking for insecure configuration options in ", "phase"),
                    ANSIThemeStr(f"{CMT_CONFIG_FILE}", "path"),
                    ANSIThemeStr("]", "phase")])
    disablestricthostkeychecking = \
        deep_get(cmtconfig_dict, DictPath("Nodes#disablestricthostkeychecking"), False)

    if not disablestricthostkeychecking:
        ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])
    else:
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    Strict SSH host key checking is disabled; this is a "
                                     "potential security threat.", "emphasis")], stderr=True)
        ansithemeprint([ANSIThemeStr("    If strict SSH host key checking is disabled other "
                                     "systems can impersonate the remote host",
                                     "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    and thus perform Man in the Middle (MITM) "
                                     "attacks.", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    It is strongly advised that you enable strict SSH "
                                     "host key checking", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    unless you are absolutely certain that your network "
                                     "environment is safe.\n", "default")], stderr=True)
        error += 1

    return abort, critical, error, warning, note
